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

	endpoint, ok := peer.Endpoint()
	if !ok {
		e.log.Debug("handshake o'tkazib yuborildi: endpoint yo'q", "peer", peer.PublicKey)
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

	if err := e.bind.Send(initiation, endpoint); err != nil {
		e.abandonHandshake(peer.PublicKey)
		e.log.Debug("initiation yuborilmadi", "peer", peer.PublicKey, "err", err)
		return
	}

	e.log.Debug("handshake boshlandi", "peer", peer.PublicKey, "endpoint", endpoint)
}

func (e *Engine) abandonHandshake(key noise.PublicKey) {
	e.handshakesMu.Lock()
	delete(e.handshakes, key)
	e.handshakesMu.Unlock()
}

// handleInitiation — responder tomoni: kelgan handshake so'roviga javob
// beradi va sessiyani o'rnatadi.
func (e *Engine) handleInitiation(packet []byte, from netip.AddrPort) {
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
	peer.SetEndpoint(from)

	if err := e.bind.Send(response, from); err != nil {
		e.log.Debug("javob yuborilmadi", "peer", initiator, "err", err)
		return
	}

	e.router.BindSession(peer, session)
	e.log.Info("sessiya o'rnatildi (responder)", "peer", initiator, "endpoint", from)

	// Bu tomonda ham kutayotgan paketlar bo'lishi mumkin.
	e.flushQueue(peer)
}

// handleResponse — initiator tomoni: javobni qabul qilib, sessiyani
// o'rnatadi va navbatdagi paketlarni yuboradi.
func (e *Engine) handleResponse(packet []byte, from netip.AddrPort) {
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

	peer.SetEndpoint(from)
	e.router.BindSession(peer, session)
	e.log.Info("sessiya o'rnatildi (initiator)", "peer", key, "endpoint", from)

	e.flushQueue(peer)
}
