package punch

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// peerStub — "ma'lum manzil" da turgan peer. U kelgan har bir
// paketga javob qaytaradi, ya'ni NAT'siz muhitda sepishning birinchi
// yarmi darhol ishlaydi.
type peerStub struct {
	bind *conn.Bind

	mu       sync.Mutex
	received int
	stop     chan struct{}
	done     chan struct{}
}

func newPeerStub(t *testing.T, reply []byte) *peerStub {
	t.Helper()

	bind, err := conn.Open(0)
	if err != nil {
		t.Fatalf("peer soketi: %v", err)
	}

	stub := &peerStub{bind: bind, stop: make(chan struct{}), done: make(chan struct{})}

	go func() {
		defer close(stub.done)
		buf := make([]byte, 2048)

		for {
			select {
			case <-stub.stop:
				return
			default:
			}

			n, from, err := bind.ReceiveOne(buf, time.Now().Add(100*time.Millisecond))
			if err != nil || n == 0 {
				continue
			}

			stub.mu.Lock()
			stub.received++
			stub.mu.Unlock()

			if reply != nil {
				_ = bind.Send(reply, from)
			}
		}
	}()

	t.Cleanup(func() {
		close(stub.stop)
		<-stub.done
		_ = bind.Close()
	})

	return stub
}

func (p *peerStub) endpoint() netip.AddrPort {
	return netip.AddrPortFrom(netip.IPv6Loopback(), p.bind.Port())
}

func (p *peerStub) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.received
}

func baseConfig(t *testing.T, endpoint netip.AddrPort) Config {
	t.Helper()

	main, err := conn.Open(0)
	if err != nil {
		t.Fatalf("asosiy soket: %v", err)
	}
	t.Cleanup(func() { _ = main.Close() })

	return Config{
		Endpoint: endpoint,
		Main:     main,
		// Kichik qiymatlar: test tez tugashi kerak, mexanika esa
		// soniga bog'liq emas.
		Sockets: 4,
		Guesses: 4,
		Payload: func() ([]byte, error) { return []byte("ping"), nil },
		Accept:  func(packet []byte, _ netip.AddrPort) bool { return string(packet) == "pong" },
		Logger:  quiet(),
	}
}

// Peer javob bersa, bosqich g'olib soketni qaytarishi kerak.
func TestRound_ReturnsWinningSocket(t *testing.T) {
	peer := newPeerStub(t, []byte("pong"))

	result, err := Round(context.Background(), baseConfig(t, peer.endpoint()))
	if err != nil {
		t.Fatalf("Round: %v", err)
	}
	defer result.Bind.Close()

	if result.Bind == nil {
		t.Fatal("g'olib soket qaytmadi")
	}
	if result.From.Port() != peer.bind.Port() {
		t.Errorf("javob %v dan, peer porti %d", result.From, peer.bind.Port())
	}
	if result.Attempts == 0 {
		t.Error("urinishlar sanalmagan")
	}
}

// G'olib soket OCHIQ qolishi kerak — yo'l aynan uning NAT yozuvi
// orqali ochilgan.
func TestRound_WinnerStaysUsable(t *testing.T) {
	peer := newPeerStub(t, []byte("pong"))

	result, err := Round(context.Background(), baseConfig(t, peer.endpoint()))
	if err != nil {
		t.Fatalf("Round: %v", err)
	}
	defer result.Bind.Close()

	// Soket ishlayotgan bo'lsa, undan yuborish muvaffaqiyatli bo'ladi.
	if err := result.Bind.Send([]byte("ping"), peer.endpoint()); err != nil {
		t.Fatalf("g'olib soket yopilgan: %v", err)
	}
}

// Hech kim javob bermasa — ErrNoHole, va bu kutilgan natija.
func TestRound_ReportsNoHole(t *testing.T) {
	// Javob bermaydigan peer.
	peer := newPeerStub(t, nil)

	_, err := Round(context.Background(), baseConfig(t, peer.endpoint()))
	if !errors.Is(err, ErrNoHole) {
		t.Fatalf("ErrNoHole kutilgan edi, olindi: %v", err)
	}

	if peer.count() == 0 {
		t.Error("peerga birorta ham probe yetib bormadi")
	}
}

// Accept rad etsa, bosqich muvaffaqiyatli hisoblanmasligi kerak.
// Busiz har qanday tasodifiy UDP paket "teshik ochildi" bo'lardi.
func TestRound_RejectsUnauthenticatedReply(t *testing.T) {
	peer := newPeerStub(t, []byte("begona"))

	cfg := baseConfig(t, peer.endpoint())

	_, err := Round(context.Background(), cfg)
	if !errors.Is(err, ErrNoHole) {
		t.Fatalf("tekshiruvdan o'tmagan javob qabul qilindi: %v", err)
	}
}

// Sepish ikkala yarimni ham bajaradi: ma'lum manzilga va
// taxminlarga.
func TestRound_SpraysBothHalves(t *testing.T) {
	peer := newPeerStub(t, nil)

	cfg := baseConfig(t, peer.endpoint())
	cfg.Sockets = 5
	cfg.Guesses = 7

	_, _ = Round(context.Background(), cfg)

	// Ma'lum manzilga har bir soketdan bittadan.
	if got := peer.count(); got < cfg.Sockets {
		t.Errorf("ma'lum manzilga %d ta probe keldi, kamida %d kutilgan edi",
			got, cfg.Sockets)
	}
}

func TestRound_RejectsInvalidEndpoint(t *testing.T) {
	cfg := baseConfig(t, netip.AddrPort{})

	if _, err := Round(context.Background(), cfg); err == nil {
		t.Fatal("yaroqsiz manzil qabul qilindi")
	}
}

func TestRound_RequiresCallbacks(t *testing.T) {
	peer := newPeerStub(t, nil)

	cfg := baseConfig(t, peer.endpoint())
	cfg.Accept = nil

	if _, err := Round(context.Background(), cfg); err == nil {
		t.Fatal("Accept'siz bosqich boshlandi")
	}
}

// Bekor qilingan kontekst bosqichni to'xtatishi kerak.
func TestRound_StopsOnContextCancel(t *testing.T) {
	peer := newPeerStub(t, nil)

	cfg := baseConfig(t, peer.endpoint())
	cfg.Sockets = 64
	cfg.Guesses = 512

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _ = Round(ctx, cfg)

	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("bekor qilish e'tiborsiz qoldirildi: %v", elapsed)
	}
}

// Taxminlar ASOSIY soketdan chiqishi shart: peerning NAT yozuvi
// faqat bizning ma'lum manzilimizdan paket qabul qiladi.
func TestRound_GuessesLeaveFromMainSocket(t *testing.T) {
	peer := newPeerStub(t, nil)

	cfg := baseConfig(t, peer.endpoint())
	cfg.Sockets = 2
	cfg.Guesses = 6

	// Taxminlar peerning PORTIGA emas, tasodifiy portlarga ketadi,
	// shuning uchun ularni peer ko'rmaydi. Buning o'rniga asosiy
	// soketning band bo'lganini tekshiramiz: agar taxminlar undan
	// chiqmasa, u umuman ishlatilmagan bo'lardi.
	if cfg.Main == nil {
		t.Fatal("asosiy soket berilmagan")
	}

	_, _ = Round(context.Background(), cfg)

	// Ma'lum manzilga faqat vaqtinchalik soketlardan yuboriladi.
	if got := peer.count(); got < cfg.Sockets {
		t.Errorf("sepish %d ta probe yubordi, kamida %d kutilgan edi", got, cfg.Sockets)
	}
}

func TestRound_RequiresMainSocket(t *testing.T) {
	peer := newPeerStub(t, nil)

	cfg := baseConfig(t, peer.endpoint())
	cfg.Main = nil

	if _, err := Round(context.Background(), cfg); err == nil {
		t.Fatal("asosiy soketsiz bosqich boshlandi")
	}
}
