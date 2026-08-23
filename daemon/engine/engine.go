// Package engine mesh datapath'ining barcha qismlarini bog'laydi.
//
//	TUN ──► router (marshrutlash) ──► noise (shifrlash) ──► UDP
//	TUN ◄── router (cryptokey check) ◄── noise (deshifrlash) ◄── UDP
//
// Engine uchta goroutine yuritadi: TUN o'quvchisi, UDP o'quvchisi va
// taymerlar (handshake, rekey, keepalive).
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/relay"
	"github.com/freco-dev/cc01/daemon/router"
	"github.com/freco-dev/cc01/daemon/stun"
)

// Device — engine ishlatadigan paket interfeysi.
//
// `*tun.Device` uni qanoatlantiradi. Interfeys sifatida ajratilgani
// testlar uchun: haqiqiy TUN qurilmasi CAP_NET_ADMIN talab qiladi,
// datapath mantiqini esa imtiyozsiz sinash mumkin bo'lishi kerak.
type Device interface {
	Name() string
	BatchSize() int
	NewBuffers() ([][]byte, []int)
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)

	// Close bloklangan Read chaqiruvini uyg'otishi SHART, aks holda
	// Engine.Close() abadiy kutib qoladi. Bir necha marta chaqirilishi
	// mumkin bo'lishi ham kerak.
	Close() error
}

// Config — engine sozlamalari.
type Config struct {
	// Identity — shu nodening doimiy kalit jufti.
	Identity *noise.Identity

	// Device — sozlangan TUN interfeysi (yoki test uchun soxta).
	Device Device

	// Bind — overlay UDP soketi.
	Bind *conn.Bind

	// Logger — nil bo'lsa slog.Default() ishlatiladi.
	Logger *slog.Logger
}

// Engine — ishlab turgan datapath.
type Engine struct {
	identity *noise.Identity
	device   Device
	bind     *conn.Bind
	router   *router.Router
	log      *slog.Logger

	// handshakes — boshlangan, lekin hali tugamagan handshake'lar.
	// Kalit: peerning public kaliti.
	handshakesMu sync.Mutex
	handshakes   map[noise.PublicKey]*noise.Handshake

	// queues — sessiya o'rnatilishini kutayotgan paketlar.
	queuesMu sync.Mutex
	queues   map[noise.PublicKey][][]byte

	// stun — public manzilni aniqlash uchun. Datapath bilan AYNI
	// soketdan ishlaydi: NAT bog'lanishi soketga bog'langan, boshqa
	// soketdan so'ralgan manzil overlay uchun yaroqsiz bo'lardi.
	stun *stun.Client

	// paths — har bir peer uchun yo'l holati (ADR-005: relay-first,
	// P2P-upgrade).
	pathsMu sync.Mutex
	paths   map[noise.PublicKey]*pathState

	// relayClient — ixtiyoriy. Bo'lsa, to'g'ridan-to'g'ri yo'l
	// ishlamaganda trafik shu orqali ketadi.
	relayMu     sync.Mutex
	relayClient *relay.Client

	// sockets — symmetric NAT ortidagi peerlar uchun AJRATILGAN
	// soketlar. Teshik aynan bitta NAT yozuvi orqali ochiladi va
	// o'sha yozuv ichki (manzil, port) juftligiga bog'langan,
	// shuning uchun boshqa soketdan yuborib bo'lmaydi.
	socketsMu     sync.Mutex
	sockets       map[noise.PublicKey]*peerSocket
	socketsClosed bool

	// punches — teshik ochish holati (qachon urinilgan, nechta marta).
	punchMu sync.Mutex
	punches map[noise.PublicKey]*punchState

	startOnce sync.Once
	closeOnce sync.Once
	closeErr  error
	closed    chan struct{}
	wg        sync.WaitGroup
}

// QueueLimit — sessiya kutayotgan paketlar uchun chegara.
//
// Handshake tugagunga qadar paketlarni buferlaymiz, aks holda birinchi
// paket har doim yo'qolardi. Chegara kerak: sessiya umuman o'rnatilmasa
// navbat cheksiz o'sib ketmasligi uchun (ARCHITECTURE.md §3.5).
const QueueLimit = 1024

func New(cfg Config) (*Engine, error) {
	if cfg.Identity == nil {
		return nil, errors.New("engine: identity berilmagan")
	}
	if cfg.Device == nil {
		return nil, errors.New("engine: TUN qurilmasi berilmagan")
	}
	if cfg.Bind == nil {
		return nil, errors.New("engine: UDP soketi berilmagan")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	e := &Engine{
		identity:   cfg.Identity,
		device:     cfg.Device,
		bind:       cfg.Bind,
		router:     router.New(),
		log:        logger.With("component", "engine"),
		handshakes: make(map[noise.PublicKey]*noise.Handshake),
		queues:     make(map[noise.PublicKey][][]byte),
		paths:      make(map[noise.PublicKey]*pathState),
		sockets:    make(map[noise.PublicKey]*peerSocket),
		punches:    make(map[noise.PublicKey]*punchState),
		closed:     make(chan struct{}),
	}

	e.stun = stun.New(e.bind.Send)
	return e, nil
}

// DiscoverPublicEndpoint STUN orqali soketning public manzilini
// aniqlaydi.
//
// Natija NAT ortidagi node uchun yagona ishlaydigan endpoint bo'ladi:
// lokal interfeys manzillari tashqaridan erishib bo'lmaydi.
func (e *Engine) DiscoverPublicEndpoint(
	ctx context.Context,
	server netip.AddrPort,
) (netip.AddrPort, error) {
	return e.stun.Discover(ctx, server)
}

// Router — peerlarni boshqarish uchun.
func (e *Engine) Router() *router.Router { return e.router }

// PublicKey — shu nodening identifikatori.
func (e *Engine) PublicKey() noise.PublicKey { return e.identity.PublicKey() }

// AddPeer peer qo'shadi va uning underlay manzilini o'rnatadi.
func (e *Engine) AddPeer(
	key noise.PublicKey,
	allowedIPs []netip.Prefix,
	endpoint netip.AddrPort,
) (*router.Peer, error) {
	peer, err := e.router.AddPeer(key, allowedIPs)
	if err != nil {
		return nil, err
	}

	if endpoint.IsValid() {
		peer.SetEndpoint(endpoint)
	}
	return peer, nil
}

// Start datapath goroutine'larini ishga tushiradi.
func (e *Engine) Start() {
	e.startOnce.Do(func() {
		e.wg.Add(3)
		go e.readTUN()
		go e.readUDP()
		go e.runTimers()

		e.log.Info("datapath ishga tushdi",
			"interface", e.device.Name(),
			"port", e.bind.Port(),
			"pubkey", e.identity.PublicKey().String())
	})
}

// Close datapath'ni to'xtatadi va goroutine'lar tugashini kutadi.
//
// Engine ishga tushgach TUN qurilmasi va UDP soketiga EGALIK QILADI:
// Close ikkalasini ham yopadi. Sababi — o'quvchi goroutine'lar
// bloklangan I/O da turadi va ularni faqat deskriptorni yopish
// uyg'otadi. Aks holda Close abadiy kutib qolardi.
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		close(e.closed)

		e.closeErr = errors.Join(
			e.closeSockets(),
			e.bind.Close(),
			e.device.Close(),
		)
	})

	e.wg.Wait()
	return e.closeErr
}

// now — testlarda vaqtni boshqarish uchun ajratilgan.
func (e *Engine) now() time.Time { return time.Now() }

func (e *Engine) isClosed() bool {
	select {
	case <-e.closed:
		return true
	default:
		return false
	}
}

// send paketni peerning endpointiga yuboradi.
func (e *Engine) send(peer *router.Peer, payload []byte) error {
	endpoint, ok := peer.Endpoint()
	if !ok {
		return fmt.Errorf("engine: %s uchun endpoint yo'q", peer.PublicKey)
	}
	return e.bindFor(peer.PublicKey).Send(payload, endpoint)
}
