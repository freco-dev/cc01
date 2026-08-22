package relay

import (
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/noise"
)

const (
	// SessionTTL — nodedan xabar kelmasa sessiya shu vaqtdan keyin
	// tozalanadi.
	//
	// Relay holatga deyarli bog'liq emas: u faqat `node_id → sessiya`
	// xaritasini yuritadi va uni yo'qotish halokatli emas — node
	// qaytadan ulanadi.
	SessionTTL = 5 * time.Minute

	sweepInterval = 30 * time.Second
)

// Server — relay tuguni.
type Server struct {
	identity *noise.Identity
	bind     *conn.Bind
	log      *slog.Logger

	mu      sync.RWMutex
	byNode  map[NodeID]*peerSession
	byIndex map[uint32]*peerSession
	now     func() time.Time

	closeOnce sync.Once
	closed    chan struct{}
	done      chan struct{}

	// stats — diagnostika uchun.
	forwarded  atomicCounter
	dropped    atomicCounter
	handshakes atomicCounter
}

// peerSession — relayga ulangan bitta node.
type peerSession struct {
	nodeID   NodeID
	session  *noise.Session
	endpoint netip.AddrPort
	lastSeen time.Time
}

// Options — server sozlamalari.
type Options struct {
	// Identity — relayning o'z kalit jufti. Uning public qismini
	// klientlar oldindan biladi (NetworkMap dagi `relays[]`).
	Identity *noise.Identity

	// Bind — UDP soketi.
	Bind *conn.Bind

	Logger *slog.Logger

	// Now — testlarda vaqtni boshqarish uchun.
	Now func() time.Time
}

func NewServer(opts Options) (*Server, error) {
	if opts.Identity == nil {
		return nil, errors.New("relay: identity berilmagan")
	}
	if opts.Bind == nil {
		return nil, errors.New("relay: soket berilmagan")
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &Server{
		identity: opts.Identity,
		bind:     opts.Bind,
		log:      logger.With("component", "relay"),
		byNode:   make(map[NodeID]*peerSession),
		byIndex:  make(map[uint32]*peerSession),
		now:      now,
		closed:   make(chan struct{}),
		done:     make(chan struct{}),
	}, nil
}

// PublicKey — relayning identifikatori; klientlar shuni bilishi kerak.
func (s *Server) PublicKey() noise.PublicKey { return s.identity.PublicKey() }

// Addr — relay tinglayotgan manzil.
func (s *Server) Addr() netip.AddrPort { return s.bind.LocalAddr() }

// Serve so'rovlarni qayta ishlaydi. Close chaqirilguncha bloklaydi.
func (s *Server) Serve() {
	defer close(s.done)

	go s.sweepLoop()

	messages := conn.NewDatagrams(conn.BatchSize, 2048)

	for {
		select {
		case <-s.closed:
			return
		default:
		}

		for i := range messages {
			messages[i].Payload = messages[i].Payload[:cap(messages[i].Payload)]
		}

		count, err := s.bind.Receive(messages)
		if err != nil {
			if errors.Is(err, conn.ErrClosed) {
				return
			}
			select {
			case <-s.closed:
				return
			default:
			}
			s.log.Debug("o'qish xatosi", "err", err)
			continue
		}

		for i := range count {
			s.handle(messages[i].Payload, messages[i].From)
		}
	}
}

func (s *Server) handle(packet []byte, from netip.AddrPort) {
	header, err := noise.ParseHeader(packet)
	if err != nil {
		s.dropped.add(1)
		return
	}

	switch header.Type {
	case noise.TypeHandshakeInit:
		s.handleHandshake(packet, from)

	case noise.TypeRelayWrap:
		s.handleRelayWrap(header, packet, from)

	case noise.TypeKeepalive:
		s.handleKeepalive(header, packet, from)

	default:
		// Relay faqat o'ram paketlarini uzatadi. Boshqa turlar
		// bu yerga tushmasligi kerak.
		s.dropped.add(1)
	}
}

// handleHandshake node bilan Noise sessiyasi quradi.
//
// IK patterni tufayli relay klientning public kalitini handshake
// davomida bilib oladi — ya'ni node_id ni klient EMAS, relay hisoblaydi.
// Bu boshqa nodening nomidan ro'yxatdan o'tishni imkonsiz qiladi.
func (s *Server) handleHandshake(packet []byte, from netip.AddrPort) {
	handshake, err := noise.StartResponder(s.identity)
	if err != nil {
		s.log.Error("responder yaratilmadi", "err", err)
		return
	}

	if err := handshake.ReadInitiation(packet); err != nil {
		s.log.Debug("handshake rad etildi", "from", from, "err", err)
		s.dropped.add(1)
		return
	}

	response, session, err := handshake.WriteResponse()
	if err != nil {
		s.log.Error("javob yozilmadi", "err", err)
		return
	}

	if err := s.bind.Send(response, from); err != nil {
		s.log.Debug("javob yuborilmadi", "to", from, "err", err)
		return
	}

	// node_id AUTENTIFIKATSIYA QILINGAN kalitdan hisoblanadi.
	nodeID := NodeIDFor(handshake.PeerStatic())

	entry := &peerSession{
		nodeID:   nodeID,
		session:  session,
		endpoint: from,
		lastSeen: s.now(),
	}

	s.mu.Lock()
	// Eski sessiya bo'lsa uning indeksini tozalaymiz — node qayta
	// ulangan bo'lishi mumkin.
	if previous, ok := s.byNode[nodeID]; ok {
		delete(s.byIndex, previous.session.LocalIndex())
	}
	s.byNode[nodeID] = entry
	s.byIndex[session.LocalIndex()] = entry
	s.mu.Unlock()

	s.handshakes.add(1)
	s.log.Info("node ulandi", "node", nodeID.Short(), "endpoint", from)
}

// handleRelayWrap paketni qabul qiluvchiga uzatadi.
func (s *Server) handleRelayWrap(header noise.Header, packet []byte, from netip.AddrPort) {
	sender, ok := s.sessionByIndex(header.ReceiverIndex)
	if !ok {
		s.dropped.add(1)
		return
	}

	_, payload, err := sender.session.Open(packet)
	if err != nil {
		s.log.Debug("deshifrlash muvaffaqiyatsiz", "node", sender.nodeID.Short(), "err", err)
		s.dropped.add(1)
		return
	}

	s.touch(sender, from)

	destination, inner, err := Unwrap(payload)
	if err != nil {
		s.dropped.add(1)
		return
	}

	target, ok := s.sessionByNode(destination)
	if !ok {
		// Qabul qiluvchi ulanmagan. Bu odatiy hol: u hali kelmagan
		// yoki uzilgan bo'lishi mumkin.
		s.log.Debug("qabul qiluvchi ulanmagan",
			"from", sender.nodeID.Short(), "to", destination.Short())
		s.dropped.add(1)
		return
	}

	// ⚠️ Jo'natuvchining ID'si SESSIYADAN olinadi, klient yuborgan
	// qiymatdan emas — aks holda kim bo'lsa o'zini boshqa node deb
	// ko'rsata olardi.
	outgoing, err := Wrap(sender.nodeID, inner)
	if err != nil {
		s.dropped.add(1)
		return
	}

	sealed, err := target.session.Seal(noise.TypeRelayWrap, outgoing)
	if err != nil {
		s.log.Debug("shifrlash muvaffaqiyatsiz", "node", target.nodeID.Short(), "err", err)
		s.dropped.add(1)
		return
	}

	if err := s.bind.Send(sealed, target.endpoint); err != nil {
		s.log.Debug("uzatilmadi", "to", target.nodeID.Short(), "err", err)
		s.dropped.add(1)
		return
	}

	s.forwarded.add(1)
}

// handleKeepalive sessiyani va endpointni yangilaydi.
//
// NAT ortidagi node uchun bu muhim: uning bog'lanishi eskirmasligi
// kerak, aks holda relay unga paket yubora olmaydi.
func (s *Server) handleKeepalive(header noise.Header, packet []byte, from netip.AddrPort) {
	entry, ok := s.sessionByIndex(header.ReceiverIndex)
	if !ok {
		s.dropped.add(1)
		return
	}

	if _, _, err := entry.session.Open(packet); err != nil {
		s.dropped.add(1)
		return
	}

	s.touch(entry, from)
}

// touch sessiyaning oxirgi faollik vaqtini va endpointini yangilaydi.
func (s *Server) touch(entry *peerSession, from netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry.lastSeen = s.now()
	entry.endpoint = from
}

func (s *Server) sessionByIndex(index uint32) (*peerSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.byIndex[index]
	return entry, ok
}

func (s *Server) sessionByNode(id NodeID) (*peerSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.byNode[id]
	return entry, ok
}

// Sessions — ulangan nodelar soni.
func (s *Server) Sessions() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byNode)
}

// Stats — uzatilgan, tashlangan paketlar va handshake'lar soni.
func (s *Server) Stats() (forwarded, dropped, handshakes int64) {
	return s.forwarded.load(), s.dropped.load(), s.handshakes.load()
}

func (s *Server) sweepLoop() {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

// sweep eskirgan sessiyalarni tozalaydi.
func (s *Server) sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	var removed int

	for id, entry := range s.byNode {
		if now.Sub(entry.lastSeen) < SessionTTL {
			continue
		}
		delete(s.byNode, id)
		delete(s.byIndex, entry.session.LocalIndex())
		removed++
	}

	return removed
}

// Close serverni to'xtatadi.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		err = s.bind.Close()
		<-s.done
	})
	return err
}

// NodeIDFor public kalitdan node_id hisoblaydi.
//
// Formula CP dagi bilan bir xil bo'lishi SHART
// (ARCHITECTURE.md §3.1.2: node_id = SHA-256(pubkey)).
func NodeIDFor(key noise.PublicKey) NodeID {
	return NodeID(sha256.Sum256(key[:]))
}
