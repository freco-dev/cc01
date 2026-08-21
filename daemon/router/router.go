// Package router overlay paketlarini peerlarga marshrutlaydi va kirish
// paketlarini soxtalashtirishdan himoyalaydi.
//
// Ikkita asosiy amal:
//
//	Chiqish: dst_ipv6 → peer → sessiya → shifrlash
//	Kirish:  receiver_index → sessiya → deshifrlash → CRYPTOKEY ROUTING
//
// Kirishdagi oxirgi qadam — bu paketning eng muhim xavfsizlik tekshiruvi
// (ARCHITECTURE.md §4.2). Usiz autentifikatsiyalangan peer boshqa
// peerning manzilidan yozib, uning nomidan gaplasha olardi.
package router

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/freco-dev/cc01/daemon/noise"
)

var (
	// ErrNoRoute — manzil hech bir peerning allowed_ips iga kirmaydi.
	ErrNoRoute = errors.New("router: manzil uchun peer topilmadi")

	// ErrNoSession — peer bor, lekin hali handshake bo'lmagan.
	ErrNoSession = errors.New("router: peer bilan sessiya yo'q")

	// ErrUnknownSession — kelgan paket noma'lum sessiya indeksiga tegishli.
	ErrUnknownSession = errors.New("router: sessiya indeksi noma'lum")

	// ErrSpoofedSource — CRYPTOKEY ROUTING buzildi: peer o'ziga
	// tegishli bo'lmagan manzildan yozmoqchi.
	ErrSpoofedSource = errors.New("router: manba manzili soxtalashtirilgan")

	// ErrPeerExists — shu public kalitli peer allaqachon bor.
	ErrPeerExists = errors.New("router: peer allaqachon mavjud")

	// ErrPrefixConflict — prefiks boshqa peerga tegishli.
	ErrPrefixConflict = errors.New("router: prefiks boshqa peerga tegishli")
)

// Router — peerlar registri va marshrutlash jadvali.
type Router struct {
	mu sync.RWMutex

	peers map[noise.PublicKey]*Peer

	// byIndex — kirish paketlari uchun: receiver_index → peer.
	// Indeksni MAHALLIY tomon tanlaydi, shuning uchun u noyob.
	byIndex map[uint32]*Peer

	routes *trie
}

func New() *Router {
	return &Router{
		peers:   make(map[noise.PublicKey]*Peer),
		byIndex: make(map[uint32]*Peer),
		routes:  newTrie(),
	}
}

// AddPeer yangi peer qo'shadi.
//
// Prefikslar boshqa peerga tegishli bo'lsa xato qaytariladi: bir manzil
// ikki peerga tegishli bo'lishi marshrutlashni ham, xavfsizlik
// tekshiruvini ham noaniq qilib qo'yadi.
func (r *Router) AddPeer(key noise.PublicKey, allowedIPs []netip.Prefix) (*Peer, error) {
	if key.IsZero() {
		return nil, errors.New("router: peer public kaliti bo'sh")
	}

	for _, prefix := range allowedIPs {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("router: prefiks yaroqsiz: %v", prefix)
		}
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("%w: %v", ErrNotIPv6, prefix)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.peers[key]; exists {
		return nil, fmt.Errorf("%w: %s", ErrPeerExists, key)
	}

	// Konflikt tekshiruvi yozishdan OLDIN — yarim qo'shilgan peer
	// qolmasligi uchun.
	for _, prefix := range allowedIPs {
		if owner := r.routes.lookup(prefix.Masked().Addr()); owner != nil {
			for _, owned := range owner.allowedIPs {
				if owned == prefix.Masked() {
					return nil, fmt.Errorf("%w: %v → %s", ErrPrefixConflict, prefix, owner.PublicKey)
				}
			}
		}
	}

	peer := &Peer{
		PublicKey:  key,
		allowedIPs: append([]netip.Prefix(nil), normalize(allowedIPs)...),
	}

	r.peers[key] = peer
	for _, prefix := range peer.allowedIPs {
		r.routes.insert(prefix, peer)
	}

	return peer, nil
}

// RemovePeer peerni va uning hamma yozuvlarini o'chiradi.
func (r *Router) RemovePeer(key noise.PublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()

	peer, ok := r.peers[key]
	if !ok {
		return
	}

	delete(r.peers, key)
	r.routes.removePeer(peer)

	for index, indexed := range r.byIndex {
		if indexed == peer {
			delete(r.byIndex, index)
		}
	}

	// Sessiyani darhol yopamiz: bekor qilingan peer keyingi paketni ham
	// yubora olmasligi kerak (ARCHITECTURE.md §3.5).
	peer.ClearSession()
}

// Peer public kalit bo'yicha peerni qaytaradi.
func (r *Router) Peer(key noise.PublicKey) (*Peer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peer, ok := r.peers[key]
	return peer, ok
}

// Peers barcha peerlarni qaytaradi.
func (r *Router) Peers() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	peers := make([]*Peer, 0, len(r.peers))
	for _, peer := range r.peers {
		peers = append(peers, peer)
	}
	return peers
}

// BindSession sessiyani peerga bog'laydi va uni indeks bo'yicha
// topiladigan qiladi.
//
// Eski sessiyaning indeksi olib tashlanmaydi: rekey paytida qisqa vaqt
// ikkala sessiya ham qabul qilinishi kerak, aks holda yo'ldagi paketlar
// yo'qoladi (ARCHITECTURE.md §3.5 — 5 sekundlik grace).
func (r *Router) BindSession(peer *Peer, session *noise.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.byIndex[session.LocalIndex()] = peer
	peer.SetSession(session)
}

// UnbindSession indeksni ro'yxatdan chiqaradi (grace tugagach).
func (r *Router) UnbindSession(index uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.byIndex, index)
}

// ─────────────────────────── chiqish ───────────────────────────

// RouteOutbound TUN'dan kelgan paket qaysi peerga ketishini aniqlaydi.
//
// Paket hali shifrlanmagan — bu ochiq matndagi ichki paket.
func (r *Router) RouteOutbound(packet []byte) (*Peer, error) {
	_, dst, err := endpoints(packet)
	if err != nil {
		return nil, err
	}

	r.mu.RLock()
	peer := r.routes.lookup(dst)
	r.mu.RUnlock()

	if peer == nil {
		return nil, fmt.Errorf("%w: %v", ErrNoRoute, dst)
	}
	if peer.Session() == nil {
		return peer, fmt.Errorf("%w: %s", ErrNoSession, peer.PublicKey)
	}

	return peer, nil
}

// ─────────────────────────── kirish ───────────────────────────

// SessionFor kelgan paketning sarlavhasidagi indeks bo'yicha peer va
// sessiyani topadi.
func (r *Router) SessionFor(index uint32) (*Peer, *noise.Session, error) {
	r.mu.RLock()
	peer, ok := r.byIndex[index]
	r.mu.RUnlock()

	if !ok {
		return nil, nil, fmt.Errorf("%w: %d", ErrUnknownSession, index)
	}

	session := peer.Session()
	if session == nil {
		return peer, nil, fmt.Errorf("%w: %s", ErrNoSession, peer.PublicKey)
	}

	return peer, session, nil
}

// VerifyInbound — CRYPTOKEY ROUTING.
//
// Deshifrlangan ichki paketning MANBA manzili shu peerning allowed_ips
// ichida bo'lishi shart. Aks holda — DROP.
//
// Bu tekshiruv nima uchun majburiy: Noise sessiyasi paket AYNAN SHU
// peerdan kelganini isbotlaydi, lekin uning ichida NIMA yozilganini emas.
// Tekshiruvsiz, tarmoqqa qonuniy ravishda ulangan har qanday node
// boshqa node'ning manzilidan paket yuborib, uning nomidan gaplasha
// olardi (ARCHITECTURE.md §4.2).
//
// Chaqirilishi SHART: har bir deshifrlangan paket uchun, istisnosiz.
func (r *Router) VerifyInbound(peer *Peer, innerPacket []byte) error {
	src, _, err := endpoints(innerPacket)
	if err != nil {
		return err
	}

	if !peer.permits(src) {
		return fmt.Errorf("%w: %v peer %s ga tegishli emas",
			ErrSpoofedSource, src, peer.PublicKey)
	}

	return nil
}

// normalize prefikslarni masked ko'rinishga keltiradi.
func normalize(prefixes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		out[i] = prefix.Masked()
	}
	return out
}
