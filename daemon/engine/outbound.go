package engine

import (
	"errors"

	"github.com/freco-dev/cc01/daemon/noise"
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

	if err := e.send(peer, sealed); err != nil {
		e.log.Debug("yuborish muvaffaqiyatsiz", "peer", peer.PublicKey, "err", err)
	}
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
