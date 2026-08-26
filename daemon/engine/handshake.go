package engine

import (
	"net/netip"

	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/router"
)

// beginHandshake peer bilan yangi handshake boshlaydi.
//
// Bir vaqtda bitta handshake: takror chaqiruvlar e'tiborsiz qoldiriladi,
// aks holda har bir navbatdagi paket yangi handshake yaratardi.
func (e *Engine) beginHandshake(peer *router.Peer) {
	if peer == nil {
		return
	}

	// Handshake ham yo'l tanlashdan o'tadi: to'g'ridan-to'g'ri yo'l
	// hali tasdiqlanmagan bo'lsa u relay orqali ketadi va ulanish
	// darhol boshlanadi (ADR-005).
	if _, _, ok := e.pathFor(peer).tracker.Best(); !ok {
		e.log.Debug("handshake o'tkazib yuborildi: yo'l yo'q", "peer", peer.PublicKey)
		return
	}

	e.handshakesMu.Lock()
	if _, inFlight := e.handshakes[peer.PublicKey]; inFlight {
		e.handshakesMu.Unlock()
		return
	}

	handshake, err := noise.StartInitiator(e.identity, peer.PublicKey)
	if err != nil {
		e.handshakesMu.Unlock()
		e.log.Error("handshake boshlanmadi", "peer", peer.PublicKey, "err", err)
		return
	}
	e.handshakes[peer.PublicKey] = handshake
	e.handshakesMu.Unlock()

	initiation, err := handshake.WriteInitiation()
	if err != nil {
		e.abandonHandshake(peer.PublicKey)
		e.log.Error("initiation yozilmadi", "peer", peer.PublicKey, "err", err)
		return
	}

	if err := e.sendVia(peer, initiation); err != nil {
		e.abandonHandshake(peer.PublicKey)
		e.log.Debug("initiation yuborilmadi", "peer", peer.PublicKey, "err", err)
		return
	}

	kind, endpoint, _ := e.pathFor(peer).tracker.Best()
	e.log.Debug("handshake boshlandi",
		"peer", peer.PublicKey, "via", kind, "endpoint", endpoint)
}

func (e *Engine) abandonHandshake(key noise.PublicKey) {
	e.handshakesMu.Lock()
	delete(e.handshakes, key)
	e.handshakesMu.Unlock()
}

// handleInitiation — responder tomoni: kelgan handshake so'roviga javob
// beradi va sessiyani o'rnatadi.
func (e *Engine) acceptInitiation(packet []byte, from netip.AddrPort, learnEndpoint bool) {
	handshake, err := noise.StartResponder(e.identity)
	if err != nil {
		e.log.Error("responder yaratilmadi", "err", err)
		return
	}

	if err := handshake.ReadInitiation(packet); err != nil {
		// Noto'g'ri kalit bilan urinish yoki buzilgan paket. Bu
		// odatiy "shovqin" bo'lishi mumkin, shuning uchun Debug.
		e.log.Debug("initiation rad etildi", "from", from, "err", err)
		return
	}

	// IK: initiatorning kim ekani endi ma'lum. U bizga tanishmi?
	initiator := handshake.PeerStatic()
	peer, known := e.router.Peer(initiator)
	if !known {
		e.log.Warn("noma'lum peerdan handshake", "pubkey", initiator, "from", from)
		return
	}

	response, session, err := handshake.WriteResponse()
	if err != nil {
		e.log.Error("javob yozilmadi", "peer", initiator, "err", err)
		return
	}

	// Endpointni javob yuborishdan OLDIN yangilaymiz: peer NAT ortida
	// bo'lishi va manzili o'zgargan bo'lishi mumkin.
	if learnEndpoint {
		peer.SetEndpoint(from)
	}

	// Javob AYNAN kelgan yo'l orqali qaytadi: relay orqali kelgan
	// handshake'ga to'g'ridan-to'g'ri javob berish ishlamaydi —
	// peer NAT ortida bo'lishi mumkin.
	var sendErr error
	if learnEndpoint {
		sendErr = e.bind.Send(response, from)
	} else {
		sendErr = e.sendViaRelay(peer, response)
	}
	if sendErr != nil {
		e.log.Debug("javob yuborilmadi", "peer", initiator, "err", sendErr)
		return
	}

	e.router.BindSession(peer, session)
	e.log.Info("sessiya o'rnatildi (responder)",
		"peer", initiator, "via", viaLabel(learnEndpoint), "endpoint", from)

	// Bu tomonda ham kutayotgan paketlar bo'lishi mumkin.
	e.flushQueue(peer)
}

// handleResponse — initiator tomoni: javobni qabul qilib, sessiyani
// o'rnatadi va navbatdagi paketlarni yuboradi.
func (e *Engine) acceptResponse(packet []byte, from netip.AddrPort, learnEndpoint bool) {
	header, err := noise.ParseHeader(packet)
	if err != nil {
		return
	}

	// Javob qaysi handshake'ga tegishli ekanini indeks bo'yicha topamiz.
	e.handshakesMu.Lock()
	var (
		key       noise.PublicKey
		handshake *noise.Handshake
	)
	for candidateKey, candidate := range e.handshakes {
		if candidate.LocalIndex() == header.ReceiverIndex {
			key, handshake = candidateKey, candidate
			break
		}
	}
	if handshake != nil {
		delete(e.handshakes, key)
	}
	e.handshakesMu.Unlock()

	if handshake == nil {
		e.log.Debug("kutilmagan handshake javobi", "index", header.ReceiverIndex, "from", from)
		return
	}

	session, err := handshake.ReadResponse(packet)
	if err != nil {
		e.log.Debug("javob rad etildi", "peer", key, "err", err)
		return
	}

	peer, known := e.router.Peer(key)
	if !known {
		// Handshake davomida peer o'chirilgan.
		return
	}

	if learnEndpoint {
		peer.SetEndpoint(from)
	}
	e.router.BindSession(peer, session)
	e.log.Info("sessiya o'rnatildi (initiator)",
		"peer", key, "via", viaLabel(learnEndpoint), "endpoint", from)

	e.flushQueue(peer)
}

// viaLabel handshake qaysi yo'l orqali kelganini bildiradi.
//
// Relay orqali kelgan paketda `from` bo'sh bo'ladi (endpoint
// o'rganilmaydi), va logda bo'sh manzil chalkash ko'rinardi.
func viaLabel(direct bool) string {
	if direct {
		return "direct"
	}
	return "relay"
}
