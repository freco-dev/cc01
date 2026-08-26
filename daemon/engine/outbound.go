package engine

import (
	"errors"

	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/path"
	"github.com/freco-dev/cc01/daemon/relay"
	"github.com/freco-dev/cc01/daemon/router"
	"github.com/freco-dev/cc01/daemon/tun"
)

// readTUN — chiqish yo'li: TUN'dan o'qiydi, marshrutlaydi, shifrlaydi,
// UDP orqali yuboradi.
func (e *Engine) readTUN() {
	defer e.wg.Done()

	bufs, sizes := e.device.NewBuffers()

	for {
		if e.isClosed() {
			return
		}

		count, err := e.device.Read(bufs, sizes, tun.Offset)
		if err != nil {
			if e.isClosed() {
				return
			}
			e.log.Error("TUN o'qish xatosi", "err", err)
			return
		}

		for i := range count {
			packet := bufs[i][tun.Offset : tun.Offset+sizes[i]]
			e.forwardOutbound(packet)
		}
	}
}

// forwardOutbound bitta chiquvchi paketni qayta ishlaydi.
func (e *Engine) forwardOutbound(packet []byte) {
	peer, err := e.router.RouteOutbound(packet)

	switch {
	case errors.Is(err, router.ErrNoSession):
		// Peer bor, sessiya yo'q: paketni navbatga qo'yamiz va
		// handshake boshlaymiz. Aks holda har bir yangi peer bilan
		// birinchi paket doim yo'qolardi.
		e.enqueue(peer, packet)
		e.beginHandshake(peer)
		return

	case err != nil:
		// Marshrut yo'q yoki paket yaroqsiz — jimgina tashlaymiz.
		// Bu odatiy hol (masalan multicast), shuning uchun Debug.
		e.log.Debug("chiquvchi paket tashlandi", "err", err)
		return
	}

	e.sealAndSend(peer, packet)
}

func (e *Engine) sealAndSend(peer *router.Peer, packet []byte) {
	session := peer.Session()
	if session == nil {
		e.enqueue(peer, packet)
		e.beginHandshake(peer)
		return
	}

	sealed, err := session.Seal(noise.TypeData, packet)
	if err != nil {
		// Nonce tugagan yoki sessiya eskirgan — yangi handshake kerak.
		e.log.Warn("shifrlash muvaffaqiyatsiz", "peer", peer.PublicKey, "err", err)
		peer.ClearSession()
		e.enqueue(peer, packet)
		e.beginHandshake(peer)
		return
	}

	if err := e.sendVia(peer, sealed); err != nil {
		e.log.Debug("yuborish muvaffaqiyatsiz", "peer", peer.PublicKey, "err", err)
	}
}

// sendVia paketni YO'L TANLASH natijasiga qarab yuboradi.
//
// ADR-005 ning amaliy ko'rinishi: tasdiqlanmagan to'g'ridan-to'g'ri
// yo'l o'rniga relay ishlatiladi, va u tasdiqlangach avtomatik
// almashadi. Chaqiruvchi qaysi yo'l ishlatilganini bilmaydi.
func (e *Engine) sendVia(peer *router.Peer, payload []byte) error {
	state := e.pathFor(peer)

	kind, endpoint, ok := state.tracker.Best()
	if !ok {
		// Yo'l kuzatuvchisi hali to'ldirilmagan — peerdagi
		// endpointga tayanamiz.
		return e.send(peer, payload)
	}

	if kind == path.KindRelay {
		return e.sendViaRelay(peer, payload)
	}

	// Peer uchun ajratilgan soket bo'lsa — AYNAN u. Yo'l o'sha
	// soketning NAT yozuvi orqali ochilgan.
	return e.bindFor(peer.PublicKey).Send(payload, endpoint)
}

// sendViaRelay paketni relay orqali uzatadi.
func (e *Engine) sendViaRelay(peer *router.Peer, payload []byte) error {
	e.relayMu.Lock()
	client := e.relayClient
	e.relayMu.Unlock()

	if client == nil {
		return errors.New("engine: relay sozlanmagan")
	}

	return client.Send(relay.NodeIDFor(peer.PublicKey), payload)
}

// enqueue paketni sessiya kutayotgan navbatga qo'shadi.
//
// Paket nusxalanadi: chaqiruvchi buferi keyingi o'qishda qayta
// ishlatiladi.
func (e *Engine) enqueue(peer *router.Peer, packet []byte) {
	if peer == nil {
		return
	}

	e.queuesMu.Lock()
	defer e.queuesMu.Unlock()

	queue := e.queues[peer.PublicKey]
	if len(queue) >= QueueLimit {
		// Navbat to'la: eng eskisini tashlaymiz. Yangi paketlar
		// odatda foydaliroq (TCP qayta yuboradi).
		copy(queue, queue[1:])
		queue = queue[:len(queue)-1]
	}

	e.queues[peer.PublicKey] = append(queue, append([]byte(nil), packet...))
}

// flushQueue sessiya o'rnatilgach navbatdagi paketlarni yuboradi.
func (e *Engine) flushQueue(peer *router.Peer) {
	e.queuesMu.Lock()
	queue := e.queues[peer.PublicKey]
	delete(e.queues, peer.PublicKey)
	e.queuesMu.Unlock()

	for _, packet := range queue {
		e.sealAndSend(peer, packet)
	}
}
