package router

import (
	"net/netip"
	"sync/atomic"

	"github.com/freco-dev/cc01/daemon/noise"
)

// Peer — mesh'dagi bitta uzoq node.
//
// `AllowedIPs` ikki vazifani bajaradi (WireGuard'dagi kabi):
//
//	CHIQISHDA — marshrutlash jadvali: qaysi manzillar shu peerga ketadi
//	KIRISHDA  — ruxsat ro'yxati: shu peer qaysi manzillardan yoza oladi
//
// Ikkinchisi — cryptokey routing. Usiz autentifikatsiyalangan peer
// boshqa peerning manzilini soxtalashtirib, uning nomidan paket yubora
// olardi (ARCHITECTURE.md §4.2).
type Peer struct {
	// PublicKey — nodening doimiy identifikatori. O'zgarmas.
	PublicKey noise.PublicKey

	// allowedIPs — nusxa saqlanadi, chaqiruvchi slice'ni keyin
	// o'zgartirsa ham bizga ta'sir qilmasligi uchun.
	allowedIPs []netip.Prefix

	// session — joriy transport sessiyasi. Rekey paytida almashadi,
	// shuning uchun atomik: datapath uni qulflashsiz o'qiydi.
	session atomic.Pointer[noise.Session]

	// endpoint — peerning UNDERLAY manzili (haqiqiy IP:port).
	//
	// U o'zgaruvchan: peer tarmoqni almashtirishi (roaming), NAT
	// jadvalining yangilanishi yoki ICE'ning yaxshiroq yo'l topishi
	// mumkin. Shuning uchun atomik va oxirgi muvaffaqiyatli paket
	// bo'yicha yangilanadi.
	endpoint atomic.Pointer[netip.AddrPort]
}

// Endpoint — peerning joriy underlay manzili.
func (p *Peer) Endpoint() (netip.AddrPort, bool) {
	value := p.endpoint.Load()
	if value == nil {
		return netip.AddrPort{}, false
	}
	return *value, true
}

// SetEndpoint underlay manzilni yangilaydi.
func (p *Peer) SetEndpoint(addr netip.AddrPort) {
	if !addr.IsValid() {
		return
	}
	p.endpoint.Store(&addr)
}

// AllowedIPs — peerning prefikslari (nusxa).
func (p *Peer) AllowedIPs() []netip.Prefix {
	return append([]netip.Prefix(nil), p.allowedIPs...)
}

// Session — joriy sessiya yoki nil (hali handshake bo'lmagan).
func (p *Peer) Session() *noise.Session {
	return p.session.Load()
}

// SetSession sessiyani almashtiradi (handshake yoki rekey tugagach).
func (p *Peer) SetSession(session *noise.Session) {
	p.session.Store(session)
}

// ClearSession sessiyani o'chiradi (peer bekor qilinganda yoki
// sessiya muddati o'tganda).
func (p *Peer) ClearSession() {
	p.session.Store(nil)
}

// permits — manzil shu peerning ruxsat ro'yxatiga kiradimi.
//
// Bu cryptokey routing tekshiruvining o'zagi.
func (p *Peer) permits(addr netip.Addr) bool {
	for _, prefix := range p.allowedIPs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
