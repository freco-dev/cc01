package engine

import (
	"net/netip"

	"github.com/freco-dev/cc01/daemon/noise"
)

// Relay orqali kelgan paketlar uchun ishlovchilar.
//
// To'g'ridan-to'g'ri kelganlaridan bitta muhim farqi bor: peerning
// endpointi YANGILANMAYDI. Paketning manba manzili — relayniki, va uni
// peerning manzili deb yozib qo'yish to'g'ridan-to'g'ri yo'lni buzardi.

// relaySentinel — relay orqali kelgan paketlar uchun "manzil yo'q"
// belgisi. Endpoint yangilanmasligini oshkora ko'rsatadi.
var relaySentinel = netip.AddrPort{}

func (e *Engine) handleInitiationViaRelay(packet []byte) {
	e.acceptInitiation(packet, relaySentinel, false)
}

func (e *Engine) handleResponseViaRelay(packet []byte) {
	e.acceptResponse(packet, relaySentinel, false)
}

func (e *Engine) handleTransportViaRelay(header noise.Header, packet []byte, outbound []byte) {
	e.acceptTransport(header, packet, relaySentinel, outbound, false)
}
