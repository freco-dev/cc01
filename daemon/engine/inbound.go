package engine

import (
	"errors"
	"net/netip"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/relay"
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
	// STUN javoblari o'sha soketga keladi. Ularni cc01 paketlaridan
	// magic cookie bo'yicha ajratamiz; sessiya indekslari ataylab shu
	// qiymatdan qochadi, ya'ni ajratish aniq (noise.randomIndex).
	if e.stun.Handle(packet) {
		return
	}

	// Relaydan kelgan paketlar o'ram ichida bo'ladi. Uni yechib,
	// ichkarisini oddiy paket sifatida qayta ishlaymiz.
	if received, mine := e.relayReceive(packet, from); mine {
		if received != nil {
			// `from` — RELAYNING manzili, peerniki emas. Shuning uchun
			// uni endpoint sifatida yozib qo'yish MUMKIN EMAS: bu
			// to'g'ridan-to'g'ri yo'lni buzardi.
			e.dispatchInner(received.Inner, outbound)
		}
		return
	}

	header, err := noise.ParseHeader(packet)
	if err != nil {
		e.log.Debug("yaroqsiz paket", "from", from, "err", err)
		return
	}

	switch header.Type {
	case noise.TypeHandshakeInit:
		e.acceptInitiation(packet, from, true)

	case noise.TypeHandshakeResp:
		e.acceptResponse(packet, from, true)

	case noise.TypeData, noise.TypeKeepalive, noise.TypeDisco:
		e.acceptTransport(header, packet, from, outbound, true)

	default:
		e.log.Debug("qo'llab-quvvatlanmaydigan tur", "type", header.Type, "from", from)
	}
}

// relayReceive relaydan kelgan paketni yechadi.
func (e *Engine) relayReceive(packet []byte, from netip.AddrPort) (*relay.Received, bool) {
	e.relayMu.Lock()
	client := e.relayClient
	e.relayMu.Unlock()

	if client == nil {
		return nil, false
	}
	return client.Handle(packet, from)
}

// dispatchInner relay o'ramidan chiqqan paketni qayta ishlaydi.
//
// Endpoint YANGILANMAYDI: paket relaydan kelgan, ya'ni uning manba
// manzili peerning haqiqiy manzili emas.
func (e *Engine) dispatchInner(packet []byte, outbound []byte) {
	header, err := noise.ParseHeader(packet)
	if err != nil {
		return
	}

	switch header.Type {
	case noise.TypeHandshakeInit:
		e.handleInitiationViaRelay(packet)

	case noise.TypeHandshakeResp:
		e.handleResponseViaRelay(packet)

	case noise.TypeData, noise.TypeKeepalive, noise.TypeDisco:
		e.handleTransportViaRelay(header, packet, outbound)
	}
}

// acceptTransport shifrlangan paketni ochadi va TUN'ga yozadi.
//
// `learnEndpoint` — paket to'g'ridan-to'g'ri kelganmi. Relay orqali
// kelgan bo'lsa `false`: manba manzili relayniki, peerniki emas.
func (e *Engine) acceptTransport(
	header noise.Header,
	packet []byte,
	from netip.AddrPort,
	outbound []byte,
	learnEndpoint bool,
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
	if learnEndpoint {
		peer.SetEndpoint(from)
	}

	// Disco — yo'l o'lchash paketi. U TUN'ga chiqmaydi va ichida
	// IPv6 paketi ham yo'q, shuning uchun cryptokey tekshiruvidan
	// oldin ajratiladi.
	if header.Type == noise.TypeDisco {
		e.handleDisco(peer, session, inner)
		return
	}

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
