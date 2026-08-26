package engine

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/path"
	"github.com/freco-dev/cc01/daemon/punch"
	"github.com/freco-dev/cc01/daemon/router"
	"github.com/freco-dev/cc01/daemon/tun"
)

// punchAfter — to'g'ridan-to'g'ri yo'l ochilmasa, qancha kutib teshik
// ochishga o'tiladi.
//
// Oddiy probe'lar bu vaqt ichida ishlab ketishi kerak (cone NAT'da
// ular bir soniyada tugaydi). Shundan keyin ham ochilmagan bo'lsa,
// sabab katta ehtimol symmetric NAT — va teshik ochish arzon amal
// emas, shuning uchun darhol boshlanmaydi.
const punchAfter = 15 * time.Second

// Muvaffaqiyatsiz bosqichdan keyingi tanaffus eksponensial o'sadi.
//
// Bitta bosqichning ehtimoli ~87%, ya'ni ikki-uch urinishda deyarli
// har doim natija bo'ladi — birinchi takrorlashlar tez bo'lishi
// kerak. Lekin bosqich yuzlab paket yuboradi va uni cheksiz
// takrorlash tarmoqqa keraksiz yuk beradi hamda port skanerlashga
// o'xshaydi. Relay esa allaqachon ishlab turibdi, ya'ni bir necha
// urinishdan keyin shoshilishning ma'nosi yo'q.
const (
	punchCooldownMin = 5 * time.Second
	punchCooldownMax = 5 * time.Minute
)

// cooldownFor navbatdagi urinishgacha kutish muddati.
func cooldownFor(attempts int) time.Duration {
	cooldown := punchCooldownMin
	for range attempts - 1 {
		cooldown *= 2
		if cooldown >= punchCooldownMax {
			return punchCooldownMax
		}
	}
	return cooldown
}

// punchState — peer bo'yicha teshik ochish holati.
type punchState struct {
	// since — peer birinchi marta "yo'l yo'q" holatida ko'rilgan
	// vaqt. Oddiy probe'larga shu paytdan boshlab vaqt beriladi.
	since time.Time

	lastTry  time.Time
	running  bool
	attempts int
}

// peerSocket — bitta peer uchun ajratilgan soket.
//
// Symmetric NAT ortida yo'l AYNAN bitta NAT yozuvi orqali ochiladi va
// o'sha yozuv ichki (manzil, port) juftligiga bog'langan. Boshqa
// soketdan yuborilgan paket boshqa tashqi portdan chiqadi va peerning
// NAT'ida rad etiladi — shuning uchun g'olib soket saqlanib qoladi.
type peerSocket struct {
	bind *conn.Bind
	stop chan struct{}
}

// bindFor peer uchun ishlatiladigan soketni qaytaradi.
//
// Ajratilgan soket bo'lmasa — asosiy soket.
func (e *Engine) bindFor(key noise.PublicKey) *conn.Bind {
	e.socketsMu.Lock()
	defer e.socketsMu.Unlock()

	if socket, ok := e.sockets[key]; ok {
		return socket.bind
	}
	return e.bind
}

// adoptSocket g'olib soketni peerga biriktiradi va uni o'qiy
// boshlaydi.
func (e *Engine) adoptSocket(key noise.PublicKey, bind *conn.Bind) {
	socket := &peerSocket{bind: bind, stop: make(chan struct{})}

	e.socketsMu.Lock()
	// Engine yopilib bo'lgan bo'lsa soketni qabul qilmaymiz: u
	// ro'yxatga tushsa ham hech kim uni yopmasdi. Bosqich yopilish
	// bilan bir vaqtda tugashi mumkin, ya'ni bu tasodifiy emas.
	if e.socketsClosed {
		e.socketsMu.Unlock()
		_ = bind.Close()
		return
	}

	previous, existed := e.sockets[key]
	e.sockets[key] = socket
	e.socketsMu.Unlock()

	if existed {
		close(previous.stop)
		_ = previous.bind.Close()
	}

	e.wg.Add(1)
	go e.readPeerSocket(socket)
}

// releaseSocket peer o'chirilganda soketni yopadi.
func (e *Engine) releaseSocket(key noise.PublicKey) {
	e.socketsMu.Lock()
	socket, ok := e.sockets[key]
	delete(e.sockets, key)
	e.socketsMu.Unlock()

	if ok {
		close(socket.stop)
		_ = socket.bind.Close()
	}
}

// closeSockets hamma ajratilgan soketni yopadi (Close paytida).
func (e *Engine) closeSockets() error {
	e.socketsMu.Lock()
	e.socketsClosed = true
	sockets := make([]*peerSocket, 0, len(e.sockets))
	for key, socket := range e.sockets {
		sockets = append(sockets, socket)
		delete(e.sockets, key)
	}
	e.socketsMu.Unlock()

	var errs []error
	for _, socket := range sockets {
		close(socket.stop)
		errs = append(errs, socket.bind.Close())
	}
	return errors.Join(errs...)
}

// readPeerSocket ajratilgan soketni o'qiydi.
//
// Paketlar asosiy soketdagi bilan BIR XIL yo'ldan o'tadi: dispatch
// paket turini o'zi aniqlaydi va sessiya indeksi bo'yicha peerni
// topadi, ya'ni qaysi soketdan kelgani ahamiyatsiz.
func (e *Engine) readPeerSocket(socket *peerSocket) {
	defer e.wg.Done()

	messages := conn.NewDatagrams(conn.BatchSize, 2048)
	outbound := make([]byte, tun.Offset+tun.DefaultMTU+128)

	for {
		select {
		case <-socket.stop:
			return
		default:
		}

		if e.isClosed() {
			return
		}

		for i := range messages {
			messages[i].Payload = messages[i].Payload[:cap(messages[i].Payload)]
		}

		count, err := socket.bind.Receive(messages)
		if err != nil {
			if errors.Is(err, conn.ErrClosed) || e.isClosed() {
				return
			}
			continue
		}

		for i := range count {
			e.dispatch(messages[i].Payload, messages[i].From, outbound)
		}
	}
}

// maybePunch peer uchun teshik ochish kerakmi va mumkinmi — hal
// qiladi. Taymer chaqiradi.
func (e *Engine) maybePunch(peer *router.Peer, now time.Time) {
	state := e.pathFor(peer)

	// Yo'l allaqachon ochiq — hech narsa kerak emas.
	if state.tracker.State() == path.StateDirectActive {
		return
	}

	// Relay ishlamayotgan bo'lsa teshik ochishning ma'nosi yo'q:
	// probe'ni shifrlash uchun sessiya kerak, sessiya esa relay
	// orqali o'rnatiladi.
	session := peer.Session()
	if session == nil {
		return
	}

	endpoint, known := state.tracker.DirectCandidate()
	if !known {
		return
	}

	key := peer.PublicKey

	e.punchMu.Lock()
	tracked, ok := e.punches[key]
	if !ok {
		tracked = &punchState{since: now}
		e.punches[key] = tracked
	}
	if tracked.running {
		e.punchMu.Unlock()
		return
	}
	// Oddiy probe'larga vaqt beramiz, keyin tanaffuslarni hisobga
	// olamiz.
	if now.Sub(tracked.since) < punchAfter {
		e.punchMu.Unlock()
		return
	}
	if !tracked.lastTry.IsZero() && now.Sub(tracked.lastTry) < cooldownFor(tracked.attempts) {
		e.punchMu.Unlock()
		return
	}
	tracked.running = true
	tracked.lastTry = now
	tracked.attempts++
	attempt := tracked.attempts
	e.punchMu.Unlock()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.runPunch(peer, session, endpoint, attempt)

		e.punchMu.Lock()
		if tracked, ok := e.punches[key]; ok {
			tracked.running = false
		}
		e.punchMu.Unlock()
	}()
}

// runPunch bitta bosqichni bajaradi.
func (e *Engine) runPunch(
	peer *router.Peer,
	session *noise.Session,
	endpoint netip.AddrPort,
	attempt int,
) {
	e.log.Info("teshik ochishga urinish (symmetric NAT)",
		"peer", peer.PublicKey, "endpoint", endpoint, "urinish", attempt)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Kontekst engine yopilganda ham bekor bo'lishi kerak.
	go func() {
		select {
		case <-e.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	result, err := punch.Round(ctx, punch.Config{
		Endpoint: endpoint,
		Main:     e.bindFor(peer.PublicKey),
		Payload: func() ([]byte, error) {
			nonce, err := path.NewNonce()
			if err != nil {
				return nil, err
			}
			return session.Seal(noise.TypeDisco, path.EncodeDisco(path.Ping, nonce))
		},
		Accept: func(packet []byte, _ netip.AddrPort) bool {
			return e.acceptPunchReply(peer, packet)
		},
		Logger: e.log,
	})
	if err != nil {
		e.log.Info("teshik ochilmadi", "peer", peer.PublicKey, "err", err)
		return
	}

	e.log.Info("teshik ochildi",
		"peer", peer.PublicKey, "peer_endpoint", result.From,
		"urinishlar", result.Attempts)

	// Endi shu peer bilan hamma trafik g'olib soketdan o'tadi va
	// peerning haqiqiy tashqi manzili ma'lum bo'ldi.
	e.adoptSocket(peer.PublicKey, result.Bind)
	peer.SetEndpoint(result.From)

	state := e.pathFor(peer)
	state.tracker.SetDirectCandidate(result.From)
}

// acceptPunchReply kelgan paket haqiqatan shu peerdan kelganini
// tekshiradi.
//
// Tekshiruvsiz har qanday tasodifiy UDP paket "teshik ochildi" deb
// hisoblanardi — va biz yuzlab tasodifiy portga yozganimiz uchun
// javob qaytarish ehtimoli past emas (ICMP emas, lekin boshqa
// xizmatlar javob berishi mumkin).
func (e *Engine) acceptPunchReply(peer *router.Peer, packet []byte) bool {
	header, err := noise.ParseHeader(packet)
	if err != nil {
		return false
	}
	if header.Type != noise.TypeDisco {
		return false
	}

	owner, session, err := e.router.SessionFor(header.ReceiverIndex)
	if err != nil || owner.PublicKey != peer.PublicKey {
		return false
	}

	// AEAD o'tsa — paket haqiqatan shu peerdan.
	if _, _, err := session.Open(packet); err != nil {
		return false
	}
	return true
}

// forgetPunch peer o'chirilganda holatni tozalaydi.
func (e *Engine) forgetPunch(key noise.PublicKey) {
	e.punchMu.Lock()
	delete(e.punches, key)
	e.punchMu.Unlock()
}
