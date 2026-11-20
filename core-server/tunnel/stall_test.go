package tunnel

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// stallConn — o'qimay qo'ygan klientning boshqaruv kanali. stall
// yoqilgach har bir Write yadro buferi to'lgandek turib qoladi: faqat
// yozish muddati (SetWriteDeadline) tugashi yoki Close uni bo'shatadi —
// haqiqiy net.Conn kabi. Qolgan hamma narsa (RemoteAddr, Read) haqiqiy
// loopback ulanishdan olinadi.
type stallConn struct {
	net.Conn

	stall   atomic.Bool
	pending atomic.Int32 // hozir turib qolgan Write'lar soni

	mu       sync.Mutex
	deadline time.Time

	closeOnce sync.Once
	closed    chan struct{}
}

func newStallConn(c net.Conn) *stallConn {
	return &stallConn{Conn: c, closed: make(chan struct{})}
}

func (c *stallConn) SetWriteDeadline(d time.Time) error {
	c.mu.Lock()
	c.deadline = d
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(d)
}

func (c *stallConn) Write(p []byte) (int, error) {
	if !c.stall.Load() {
		return c.Conn.Write(p)
	}
	c.pending.Add(1)
	defer c.pending.Add(-1)

	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *stallConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *stallConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// openStalledHTTP HTTP tunnel ochadi (TunnelOpened yetib boradi), keyin
// boshqaruv kanalini "to'xtatadi".
func openStalledHTTP(t *testing.T, maxConns int, writeTimeout time.Duration) (*HTTPTunnel, *stallConn) {
	t.Helper()
	srv, cli := loopback(t)
	ev := newStallConn(srv)

	tn, err := NewHTTP("stall.test", ev, maxConns)
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	tn.writeTimeout = writeTimeout
	t.Cleanup(tn.Close)
	// Cleanup'lar teskari tartibda: kanal tn.Close dan OLDIN yopiladi,
	// shunda muvaffaqiyatsiz testda ham turib qolgan yozuvchi bo'shaydi.
	t.Cleanup(func() { _ = ev.Close() })
	tn.Open()
	if err := tn.WriteOpened(&cc01v1.TunnelOpened{Hostname: "stall.test"}); err != nil {
		t.Fatalf("WriteOpened: %v", err)
	}
	if readFrame(t, cli).GetTunnelOpened() == nil {
		t.Fatal("birinchi freym TunnelOpened bo'lishi kerak")
	}
	ev.stall.Store(true)
	return tn, ev
}

// acceptStalled ommaviy ulanishni fonda qabul qiladi va uning
// ConnectionReceived freymi kanalda turib qolguncha kutadi.
func acceptStalled(t *testing.T, tn *HTTPTunnel, ev *stallConn) (net.Conn, <-chan error) {
	t.Helper()
	pub, pubClient := loopback(t)
	errc := make(chan error, 1)
	go func() { errc <- tn.PublicConnectionHandler(pub, []byte("GET / HTTP/1.1\r\n")) }()
	deadline := time.Now().Add(ioTimeout)
	for ev.pending.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("ConnectionReceived yozuvi boshlanmadi")
		}
		time.Sleep(time.Millisecond)
	}
	return pubClient, errc
}

// returnsWithin f ni fonda ishga tushiradi va u d ichida qaytishini
// talab qiladi.
func returnsWithin(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s %s ichida qaytmadi (kanalga yozuvchi ortida qotib qoldi)", what, d)
	}
}

// Kanalga yozish consMx ostida bajarilmaydi: yozuvchi muddatsiz (bu yerda
// soatlab) turib qolsa ham SetMaxConns (tarif yangilanishi) va Close
// (tunnel yopilishi, ro'yxatdan o'chirish) kutmaydi.
func TestStalledEventConn_DoesNotHoldConsMx(t *testing.T) {
	tn, ev := openStalledHTTP(t, 10, time.Hour)
	pubClient, errc := acceptStalled(t, tn, ev)

	returnsWithin(t, time.Second, "SetMaxConns", func() { tn.SetMaxConns(3) })
	returnsWithin(t, time.Second, "MaxConns", func() {
		if n := tn.MaxConns(); n != 3 {
			t.Errorf("MaxConns = %d, 3 kutilgan", n)
		}
	})
	returnsWithin(t, time.Second, "Close", tn.Close)

	// Close band qilingan (freymi hali yozilmagan) ulanishni ham yopadi.
	expectClosed(t, pubClient)

	// Kanal yopilgach turib qolgan yozuvchi xato bilan qaytadi.
	_ = ev.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("yozilmagan ConnectionReceived uchun xato kutilgan edi")
		}
	case <-time.After(ioTimeout):
		t.Fatal("PublicConnectionHandler qaytmadi")
	}
}

// Har bir freym yozuvining muddati bor: to'xtab qolgan klient Notify'ni
// (bekor qilish bildirishnomasi) abadiy ushlab tura olmaydi. Muddat
// tugagach kanal buzilgan deb belgilanadi va yopiladi — qisman yozilgan
// freymdan keyin oqim tiklanmaydi.
func TestStalledEventConn_WriteDeadlineReleasesNotify(t *testing.T) {
	const timeout = 200 * time.Millisecond
	tn, ev := openStalledHTTP(t, 10, timeout)
	pubClient, errc := acceptStalled(t, tn, ev)

	var notifyErr error
	returnsWithin(t, 2*time.Second, "Notify", func() {
		notifyErr = tn.Notify("TOKEN_REVOKED", "token bekor qilingan")
	})
	if !errors.Is(notifyErr, ErrEventConnBroken) {
		t.Fatalf("ErrEventConnBroken kutilgan edi, olindi: %v", notifyErr)
	}

	select {
	case err := <-errc:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("yozish muddati xatosi kutilgan edi, olindi: %v", err)
		}
	case <-time.After(ioTimeout):
		t.Fatal("PublicConnectionHandler qaytmadi")
	}
	expectClosed(t, pubClient)
	if !ev.isClosed() {
		t.Fatal("muddati o'tgan yozuvdan keyin boshqaruv kanali yopilishi kerak")
	}

	// Band qilingan o'rin bo'shatilgan.
	tn.consMx.Lock()
	left := len(tn.publicCons) + len(tn.initialBuffer)
	tn.consMx.Unlock()
	if left != 0 {
		t.Fatalf("muvaffaqiyatsiz ulanish ro'yxatda qoldi: %d", left)
	}

	// Kanal buzilgan: yangi ulanish freym yozishga urinmasdan rad etiladi.
	late, lateClient := loopback(t)
	returnsWithin(t, time.Second, "kechikkan ulanish", func() {
		if err := tn.PublicConnectionHandler(late, nil); !errors.Is(err, ErrNotOpened) {
			t.Errorf("ErrNotOpened kutilgan edi, olindi: %v", err)
		}
	})
	expectClosed(t, lateClient)
}

// Limitdan oshgan ulanishlar uchun RateLimited freymlari soni
// cheklanmagan — ular ham muddat bilan yoziladi.
func TestStalledEventConn_RateLimitedFrameHasDeadline(t *testing.T) {
	tn, ev := openStalledHTTP(t, 0, 200*time.Millisecond)
	pub, pubClient := loopback(t)
	returnsWithin(t, 2*time.Second, "rad etilgan ulanish", func() {
		if err := tn.PublicConnectionHandler(pub, nil); err == nil {
			t.Error("limit xatosi kutilgan edi")
		}
	})
	expectClosed(t, pubClient)
	if !ev.isClosed() {
		t.Fatal("muddati o'tgan yozuvdan keyin boshqaruv kanali yopilishi kerak")
	}
}
