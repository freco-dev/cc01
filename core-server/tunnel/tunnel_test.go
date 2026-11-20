package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/freco-dev/cc01/core-server/events"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// Barcha testlar haqiqiy loopback TCP ulanishlari orqali ishlaydi:
// boshqaruv kanali ham, ommaviy/xususiy ulanishlar ham.

const ioTimeout = 3 * time.Second

// loopback bir juft bog'langan TCP ulanish qaytaradi: server tomoni
// (RemoteAddr — *net.TCPAddr) va klient tomoni.
func loopback(t *testing.T) (server net.Conn, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server = <-accepted
	if server == nil {
		t.Fatal("accept muvaffaqiyatsiz")
	}
	t.Cleanup(func() {
		server.Close()
		client.Close()
	})
	return server, client
}

func readFrame(t *testing.T, c net.Conn) *cc01v1.Frame {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(ioTimeout))
	frame, err := events.ReadFrame(c)
	if err != nil {
		t.Fatalf("freym o'qilmadi: %v", err)
	}
	return frame
}

func readConnectionReceived(t *testing.T, c net.Conn) *cc01v1.ConnectionReceived {
	t.Helper()
	frame := readFrame(t, c)
	got := frame.GetConnectionReceived()
	if got == nil {
		t.Fatalf("ConnectionReceived kutilgan edi, olindi: %v", frame)
	}
	return got
}

// expectNoFrame boshqaruv kanalida qisqa vaqt ichida freym yo'qligini tekshiradi.
func expectNoFrame(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	frame, err := events.ReadFrame(c)
	if err == nil {
		t.Fatalf("freym kutilmagan edi, olindi: %v", frame)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("timeout kutilgan edi, olindi: %v", err)
	}
}

// expectClosed ulanish uzilganini (EOF yoki reset) tekshiradi.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(ioTimeout))
	buf := make([]byte, 16)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("ulanish yopilmadi")
		}
		return
	}
}

func dialPort(t *testing.T, port uint16) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial %d: %v", port, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// pair xususiy serverga ulanib, ommaviy ulanish portini yuboradi —
// CLI shunday qiladi.
func pair(t *testing.T, privatePort uint16, publicPort uint32) net.Conn {
	t.Helper()
	c := dialPort(t, privatePort)
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(publicPort))
	if _, err := c.Write(buf); err != nil {
		t.Fatalf("port yozilmadi: %v", err)
	}
	return c
}

// primePrivate xususiy serverning Accept sikli ishga tushganini
// isbotlaydi (Close undan oldin chaqirilmasligi uchun): noma'lum port
// yuboriladi va server ulanishni yopishi kutiladi.
func primePrivate(t *testing.T, tn Tunnel) {
	t.Helper()
	c := pair(t, tn.PrivateServerPort(), 0xFFFF)
	expectClosed(t, c)
}

func openTCP(t *testing.T, maxConns int) (*TCPTunnel, net.Conn) {
	t.Helper()
	srv, cli := loopback(t)
	tn, err := NewTCP("tcp.test", srv, maxConns)
	if err != nil {
		t.Fatalf("NewTCP: %v", err)
	}
	t.Cleanup(tn.Close)
	tn.Open()
	primePrivate(t, tn)
	if err := tn.WriteOpened(&cc01v1.TunnelOpened{Hostname: "tcp.test"}); err != nil {
		t.Fatalf("WriteOpened: %v", err)
	}
	if readFrame(t, cli).GetTunnelOpened() == nil {
		t.Fatal("birinchi freym TunnelOpened bo'lishi kerak")
	}
	return tn, cli
}

func openHTTP(t *testing.T, maxConns int) (*HTTPTunnel, net.Conn) {
	t.Helper()
	srv, cli := loopback(t)
	tn, err := NewHTTP("http.test", srv, maxConns)
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	t.Cleanup(tn.Close)
	tn.Open()
	primePrivate(t, tn)
	if err := tn.WriteOpened(&cc01v1.TunnelOpened{Hostname: "http.test"}); err != nil {
		t.Fatalf("WriteOpened: %v", err)
	}
	if readFrame(t, cli).GetTunnelOpened() == nil {
		t.Fatal("birinchi freym TunnelOpened bo'lishi kerak")
	}
	return tn, cli
}

// Interfeys to'liq amalga oshirilganini kompilyatsiya vaqtida tekshiramiz.
var (
	_ Tunnel = (*HTTPTunnel)(nil)
	_ Tunnel = (*TCPTunnel)(nil)
)

func TestSetMaxConns_AppliesToNewConnections(t *testing.T) {
	tn, control := openTCP(t, 1)
	if got := tn.MaxConns(); got != 1 {
		t.Fatalf("MaxConns: 1 kutilgan, %d olindi", got)
	}

	// 1-ulanish juftlanmagan holda qoladi va limitni to'ldiradi.
	first := dialPort(t, tn.PublicServerPort())
	if readConnectionReceived(t, control).GetRateLimited() {
		t.Fatal("1-ulanish limitga tushmasligi kerak")
	}

	// 2-ulanish eski limit bo'yicha rad etiladi.
	second := dialPort(t, tn.PublicServerPort())
	if !readConnectionReceived(t, control).GetRateLimited() {
		t.Fatal("2-ulanish limitga tushishi kerak edi")
	}
	expectClosed(t, second)

	// Limit jonli oshiriladi: mavjud ulanish saqlanadi, yangisi o'tadi.
	tn.SetMaxConns(3)
	if got := tn.MaxConns(); got != 3 {
		t.Fatalf("MaxConns: 3 kutilgan, %d olindi", got)
	}
	_ = dialPort(t, tn.PublicServerPort())
	if readConnectionReceived(t, control).GetRateLimited() {
		t.Fatal("yangi limitdan keyin ulanish qabul qilinishi kerak edi")
	}

	tn.consMx.Lock()
	n := len(tn.publicCons)
	tn.consMx.Unlock()
	if n != 2 {
		t.Fatalf("2 ta juftlanmagan ulanish kutilgan, %d", n)
	}

	// Pasaytirish mavjud ulanishlarni uzmaydi.
	tn.SetMaxConns(1)
	_ = first.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := first.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("mavjud ulanish uzilmasligi kerak edi: %v", err)
	}
}

func TestClose_ClosesPairedConnections(t *testing.T) {
	tn, control := openTCP(t, 10)

	public := dialPort(t, tn.PublicServerPort())
	received := readConnectionReceived(t, control)
	private := pair(t, tn.PrivateServerPort(), received.GetClientPort())

	// Ko'prik ishlayotganini tekshiramiz (juftlik ro'yxatga olingan).
	if _, err := public.Write([]byte("ping")); err != nil {
		t.Fatalf("yozish: %v", err)
	}
	_ = private.SetReadDeadline(time.Now().Add(ioTimeout))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(private, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("ko'prik ishlamadi: %q %v", buf, err)
	}

	// Juftlanmagan ulanish ham bo'lsin.
	unpaired := dialPort(t, tn.PublicServerPort())
	readConnectionReceived(t, control)

	tn.consMx.Lock()
	pairs := len(tn.pairs)
	tn.consMx.Unlock()
	if pairs != 1 {
		t.Fatalf("1 ta juftlik kutilgan, %d", pairs)
	}

	tn.Close()
	tn.Close() // qayta chaqirish xavfsiz

	expectClosed(t, public)
	expectClosed(t, private)
	expectClosed(t, unpaired)

	deadline := time.Now().Add(ioTimeout)
	for {
		tn.consMx.Lock()
		pairs, cons := len(tn.pairs), len(tn.publicCons)
		tn.consMx.Unlock()
		if pairs == 0 && cons == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Close dan keyin qoldi: pairs=%d publicCons=%d", pairs, cons)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConnectionBeforeOpenedIsRejected(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		srv, control := loopback(t)
		tn, err := NewTCP("tcp.test", srv, 10)
		if err != nil {
			t.Fatalf("NewTCP: %v", err)
		}
		t.Cleanup(tn.Close)
		tn.Open()
		primePrivate(t, tn)

		early := dialPort(t, tn.PublicServerPort())
		expectClosed(t, early)
		expectNoFrame(t, control) // freym yozilmaydi

		if err := tn.WriteOpened(&cc01v1.TunnelOpened{Hostname: "tcp.test"}); err != nil {
			t.Fatalf("WriteOpened: %v", err)
		}
		if readFrame(t, control).GetTunnelOpened() == nil {
			t.Fatal("birinchi freym TunnelOpened bo'lishi kerak")
		}

		_ = dialPort(t, tn.PublicServerPort())
		if readConnectionReceived(t, control).GetRateLimited() {
			t.Fatal("ochilgandan keyin ulanish qabul qilinishi kerak")
		}
	})

	t.Run("http", func(t *testing.T) {
		srv, control := loopback(t)
		tn, err := NewHTTP("http.test", srv, 10)
		if err != nil {
			t.Fatalf("NewHTTP: %v", err)
		}
		t.Cleanup(tn.Close)

		pub, pubClient := loopback(t)
		err = tn.PublicConnectionHandler(pub, []byte("GET / HTTP/1.1\r\n"))
		if !errors.Is(err, ErrNotOpened) {
			t.Fatalf("ErrNotOpened kutilgan edi, olindi: %v", err)
		}
		expectClosed(t, pubClient)
		expectNoFrame(t, control)

		tn.consMx.Lock()
		cons, bufs := len(tn.publicCons), len(tn.initialBuffer)
		tn.consMx.Unlock()
		if cons != 0 || bufs != 0 {
			t.Fatalf("rad etilgan ulanish saqlanib qoldi: publicCons=%d initialBuffer=%d", cons, bufs)
		}
	})
}

func TestNotify_WritesClosureFrameUnderLock(t *testing.T) {
	tn, control := openHTTP(t, 1000)

	const n = 40
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		pub, _ := loopback(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- tn.PublicConnectionHandler(pub, bytes.Repeat([]byte("x"), 64))
		}()
	}

	notified := make(chan error, 1)
	close(start)
	go func() { notified <- tn.Notify("PLAN_SUSPENDED", "tarif to'xtatilgan") }()
	wg.Wait()
	if err := <-notified; err != nil {
		t.Fatalf("Notify: %v", err)
	}
	close(results)

	accepted := 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrNotOpened):
		default:
			t.Fatalf("kutilmagan xato: %v", err)
		}
	}

	// Har bir freym butun o'qiladi; yopilish freymidan keyin boshqa freym yo'q.
	for i := 0; i < accepted; i++ {
		readConnectionReceived(t, control)
	}
	closure := readFrame(t, control).GetTunnelOpened()
	if closure == nil {
		t.Fatal("yopilish freymi (TunnelOpened) kutilgan edi")
	}
	if closure.GetErrorCode() != "PLAN_SUSPENDED" || closure.GetErrorMessage() != "tarif to'xtatilgan" {
		t.Fatalf("noto'g'ri yopilish freymi: %v", closure)
	}
	expectNoFrame(t, control)

	// Bildirishnomadan keyin yangi ulanish freymsiz rad etiladi.
	late, lateClient := loopback(t)
	if err := tn.PublicConnectionHandler(late, nil); !errors.Is(err, ErrNotOpened) {
		t.Fatalf("ErrNotOpened kutilgan edi, olindi: %v", err)
	}
	expectClosed(t, lateClient)
	expectNoFrame(t, control)
}

func TestNotify_EmptyMessageFallsBackToCode(t *testing.T) {
	tn, control := openHTTP(t, 10)
	if err := tn.Notify("TOKEN_REVOKED", ""); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	closure := readFrame(t, control).GetTunnelOpened()
	if closure.GetErrorCode() != "TOKEN_REVOKED" || closure.GetErrorMessage() == "" {
		t.Fatalf("klient yopilishni ajrata olishi uchun xabar bo'sh bo'lmasligi kerak: %v", closure)
	}
}

func TestHTTPInitialBuffer_NoRace(t *testing.T) {
	tn, control := openHTTP(t, 1000)

	const n = 20
	expected := make(map[uint32][]byte, n)
	publics := make([]net.Conn, n)
	for i := 0; i < n; i++ {
		pub, _ := loopback(t)
		publics[i] = pub
		port := uint32(pub.RemoteAddr().(*net.TCPAddr).Port)
		expected[port] = []byte(fmt.Sprintf("GET /%02d HTTP/1.1\r\n", i))
	}

	var wg sync.WaitGroup
	for _, pub := range publics {
		wg.Add(1)
		go func() {
			defer wg.Done()
			port := uint32(pub.RemoteAddr().(*net.TCPAddr).Port)
			if err := tn.PublicConnectionHandler(pub, expected[port]); err != nil {
				t.Errorf("PublicConnectionHandler: %v", err)
			}
		}()
	}

	// Juftlash ommaviy ulanishlar qabul qilinayotgan paytda boradi.
	for i := 0; i < n; i++ {
		received := readConnectionReceived(t, control)
		want, ok := expected[received.GetClientPort()]
		if !ok {
			t.Fatalf("noma'lum port: %d", received.GetClientPort())
		}
		private := pair(t, tn.PrivateServerPort(), received.GetClientPort())
		_ = private.SetReadDeadline(time.Now().Add(ioTimeout))
		got := make([]byte, len(want))
		if _, err := io.ReadFull(private, got); err != nil {
			t.Fatalf("boshlang'ich bufer o'qilmadi: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("boshlang'ich bufer: %q kutilgan, %q olindi", want, got)
		}
	}
	wg.Wait()

	tn.consMx.Lock()
	bufs := len(tn.initialBuffer)
	tn.consMx.Unlock()
	if bufs != 0 {
		t.Fatalf("juftlangandan keyin initialBuffer bo'sh bo'lishi kerak, %d", bufs)
	}
}

func TestHTTPInitialBuffer_NotKeptForRateLimited(t *testing.T) {
	tn, control := openHTTP(t, 1)

	first, _ := loopback(t)
	if err := tn.PublicConnectionHandler(first, []byte("GET /a")); err != nil {
		t.Fatalf("1-ulanish: %v", err)
	}
	readConnectionReceived(t, control)

	second, _ := loopback(t)
	if err := tn.PublicConnectionHandler(second, []byte("GET /b")); err == nil {
		t.Fatal("2-ulanish limitga tushishi kerak edi")
	}
	if !readConnectionReceived(t, control).GetRateLimited() {
		t.Fatal("RateLimited freymi kutilgan edi")
	}

	tn.consMx.Lock()
	bufs := len(tn.initialBuffer)
	tn.consMx.Unlock()
	if bufs != 1 {
		t.Fatalf("faqat qabul qilingan ulanish buferi qolishi kerak, %d", bufs)
	}
}

func TestSetMaxConns_Concurrent(t *testing.T) {
	tn, control := openHTTP(t, 5)
	go func() { _, _ = io.Copy(io.Discard, control) }()

	const n = 30
	publics := make([]net.Conn, n)
	for i := range publics {
		publics[i], _ = loopback(t)
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			tn.SetMaxConns(1 + i%7)
		}()
		go func() {
			defer wg.Done()
			if got := tn.MaxConns(); got < 1 || got > 7 {
				t.Errorf("MaxConns oralig'idan tashqari: %d", got)
			}
		}()
		go func() {
			defer wg.Done()
			_ = tn.PublicConnectionHandler(publics[i], []byte("GET /"))
		}()
	}
	wg.Wait()

	tn.SetMaxConns(128)
	if got := tn.MaxConns(); got != 128 {
		t.Fatalf("MaxConns: 128 kutilgan, %d olindi", got)
	}
}

func TestClose_RejectsLateConnections(t *testing.T) {
	tn, control := openHTTP(t, 10)
	tn.Close()

	late, lateClient := loopback(t)
	if err := tn.PublicConnectionHandler(late, []byte("GET /")); !errors.Is(err, ErrClosed) {
		t.Fatalf("ErrClosed kutilgan edi, olindi: %v", err)
	}
	expectClosed(t, lateClient)
	expectNoFrame(t, control)

	tn.consMx.Lock()
	cons, bufs := len(tn.publicCons), len(tn.initialBuffer)
	tn.consMx.Unlock()
	if cons != 0 || bufs != 0 {
		t.Fatalf("yopilgan tunnelda ulanish saqlandi: publicCons=%d initialBuffer=%d", cons, bufs)
	}
}
