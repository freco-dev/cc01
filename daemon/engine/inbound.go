package engine

import (
	"errors"
	"net/netip"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/tun"
)

// readUDP — kirish yo'li: UDP'dan o'qiydi, turini aniqlaydi va
// tegishli ishlovchiga uzatadi.
func (e *Engine) readUDP() {
	defer e.wg.Done()

	messages := conn.NewDatagrams(conn.BatchSize, 2048)

	// TUN'ga yozish uchun headroom'li bufer.
	outbound := make([]byte, tun.Offset+tun.DefaultMTU+128)

	for {
		if e.isClosed() {
			return
		}

		// Buferlar Receive'da qisqartiriladi, shuning uchun har
		// aylanishda to'liq sig'imni tiklaymiz.
		for i := range messages {
			messages[i].Payload = messages[i].Payload[:cap(messages[i].Payload)]
		}

		count, err := e.bind.Receive(messages)
		if err != nil {
			if errors.Is(err, conn.ErrClosed) || e.isClosed() {
				return
			}
			e.log.Error("UDP o'qish xatosi", "err", err)
			continue
		}

		for i := range count {
			e.dispatch(messages[i].Payload, messages[i].From, outbound)
		}
	}
}

// dispatch paket turiga qarab yo'naltiradi.
func (e *Engine) dispatch(packet []byte, from netip.AddrPort, outbound []byte) {
	header, err := noise.ParseHeader(packet)
	if err != nil {
		e.log.Debug("yaroqsiz paket", "from", from, "err", err)
		return
	}

	switch header.Type {
	case noise.TypeHandshakeInit:
		e.handleInitiation(packet, from)

	case noise.TypeHandshakeResp:
		e.handleResponse(packet, from)

	case noise.TypeData, noise.TypeKeepalive:
		e.handleTransport(header, packet, from, outbound)

	default:
		e.log.Debug("qo'llab-quvvatlanmaydigan tur", "type", header.Type, "from", from)
	}
}

// handleTransport shifrlangan paketni ochadi va TUN'ga yozadi.
func (e *Engine) handleTransport(
	header noise.Header,
	packet []byte,
	from netip.AddrPort,
	outbound []byte,
) {
	peer, session, err := e.router.SessionFor(header.ReceiverIndex)
	if err != nil {
		e.log.Debug("sessiya topilmadi", "index", header.ReceiverIndex, "from", from)
		return
	}

	_, inner, err := session.Open(packet)
	if err != nil {
		// Takroriy paket yoki buzilgan shifr matn. Ikkalasi ham
		// hujum belgisi bo'lishi mumkin — lekin qayta tartiblangan
		// tarmoqda ham uchraydi, shuning uchun Debug.
		e.log.Debug("deshifrlash muvaffaqiyatsiz", "peer", peer.PublicKey, "err", err)
		return
	}

	// AEAD o'tdi — paket haqiqatan shu peerdan. Endpointni yangilaymiz
	// (roaming va NAT jadvalini kuzatish). Buni faqat autentifikatsiya
	// qilingan paketdan keyin qilamiz, aks holda soxta paket peerni
	// boshqa manzilga "ko'chirib" yuborardi.
	peer.SetEndpoint(from)

	// Keepalive'da ichki paket YO'Q — tekshiradigan ham, TUN'ga
	// yozadigan ham narsa yo'q.
	//
	// ⚠️ Bu tekshiruv cryptokey routing'dan OLDIN turishi shart.
	// Aks holda bo'sh yukni IPv6 paketi sifatida parse qilishga urinib,
	// har bir keepalive "soxtalashtirish" ogohlantirishini keltirib
	// chiqaradi. Bunday soxta signallar operatorni haqiqiy
	// ogohlantirishlarga befarq qilib qo'yadi.
	//
	// Xavfsizlikka ta'siri yo'q: bo'sh paketdan TUN'ga hech narsa
	// yozilmaydi, ya'ni soxtalashtiradigan narsaning o'zi yo'q.
	if header.Type == noise.TypeKeepalive || len(inner) == 0 {
		return
	}

	// ═══ CRYPTOKEY ROUTING ═══
	// Deshifrlangan paketning manba manzili shu peerga tegishli
	// bo'lishi SHART (ARCHITECTURE.md §4.2). TUN'ga yozadigan har bir
	// paket uchun, istisnosiz.
	if err := e.router.VerifyInbound(peer, inner); err != nil {
		e.log.Warn("SOXTALASHTIRILGAN PAKET TASHLANDI",
			"peer", peer.PublicKey, "from", from, "err", err)
		return
	}

	if tun.Offset+len(inner) > len(outbound) {
		e.log.Warn("paket buferga sig'madi", "size", len(inner))
		return
	}

	copy(outbound[tun.Offset:], inner)
	if _, err := e.device.Write([][]byte{outbound[:tun.Offset+len(inner)]}, tun.Offset); err != nil {
		e.log.Error("TUN'ga yozish xatosi", "err", err)
	}
}
