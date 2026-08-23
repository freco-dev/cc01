package engine

import (
	"sync"
	"time"

	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/path"
	"github.com/freco-dev/cc01/daemon/relay"
	"github.com/freco-dev/cc01/daemon/router"
)

// pathState — bitta peer uchun yo'l holati va kutilayotgan probe'lar.
type pathState struct {
	tracker *path.Tracker

	mu sync.Mutex
	// pending — yuborilgan, lekin hali javob kelmagan probe'lar:
	// nonce → (yo'l turi, yuborilgan vaqt).
	pending map[uint64]pendingProbe
	// nextProbe — keyingi tekshiruv vaqti.
	nextProbe time.Time
}

type pendingProbe struct {
	kind path.Kind
	sent time.Time
}

func newPathState() *pathState {
	return &pathState{
		tracker: path.NewTracker(),
		pending: make(map[uint64]pendingProbe),
	}
}

// pathFor peer uchun yo'l holatini qaytaradi, kerak bo'lsa yaratadi.
//
// Har chaqirilganda peerning joriy endpointi va relay holati
// kuzatuvchiga uzatiladi. Buni faqat taymerga qoldirish MUMKIN EMAS:
// birinchi paket taymer tikidan oldin kelishi mumkin, va o'shanda
// kuzatuvchi bo'sh bo'lsa handshake umuman boshlanmasdi.
//
// Ikkala `Set*` chaqiruvi ham o'zgarish bo'lmasa arzon: ular
// qiymatni solishtirib, bir xil bo'lsa darhol qaytadi.
func (e *Engine) pathFor(peer *router.Peer) *pathState {
	e.pathsMu.Lock()
	state, ok := e.paths[peer.PublicKey]
	if !ok {
		state = newPathState()
		e.paths[peer.PublicKey] = state
	}
	e.pathsMu.Unlock()

	if endpoint, has := peer.Endpoint(); has {
		state.tracker.SetDirectCandidate(endpoint)
	}
	if endpoint, has := e.relayEndpoint(); has {
		state.tracker.SetRelay(endpoint, e.now())
	}

	return state
}

// forgetPath peer o'chirilganda holatni tozalaydi.
//
// Yo'l holati bilan birga peerga ajratilgan soket ham yopiladi va
// teshik ochish tarixi unutiladi: peer qaytib kelsa, u boshqa NAT
// yozuvi bilan keladi va eskisi yaroqsiz.
func (e *Engine) forgetPath(key noise.PublicKey) {
	e.pathsMu.Lock()
	delete(e.paths, key)
	e.pathsMu.Unlock()

	e.releaseSocket(key)
	e.forgetPunch(key)
}

// reapOrphans routerdan ketgan peerlarning holatini tozalaydi.
//
// Peerlarni Control Plane olib tashlaydi va u buni to'g'ridan-to'g'ri
// router orqali qiladi — engine bu haqda xabar olmaydi. Kuzatuvchi
// sifatida ro'yxatdan o'tish o'rniga davriy solishtirish tanlandi: u
// peer qaysi yo'l bilan ketganidan qat'i nazar ishlaydi.
//
// Bu shunchaki tartib masalasi emas: har bir ajratilgan soket ochiq
// fayl deskriptori va o'z goroutine'i, ya'ni tozalanmasa ular
// to'planib boraveradi.
func (e *Engine) reapOrphans() {
	alive := make(map[noise.PublicKey]struct{})
	for _, peer := range e.router.Peers() {
		alive[peer.PublicKey] = struct{}{}
	}

	e.pathsMu.Lock()
	var gone []noise.PublicKey
	for key := range e.paths {
		if _, ok := alive[key]; !ok {
			gone = append(gone, key)
		}
	}
	e.pathsMu.Unlock()

	// Ajratilgan soket bo'lsa-yu, yo'l holati bo'lmasa ham tozalaymiz.
	e.socketsMu.Lock()
	for key := range e.sockets {
		if _, ok := alive[key]; !ok {
			gone = append(gone, key)
		}
	}
	e.socketsMu.Unlock()

	for _, key := range gone {
		e.log.Debug("peer ketdi, holati tozalanmoqda", "peer", key)
		e.forgetPath(key)
	}
}

func (e *Engine) relayEndpoint() (netipAddrPort, bool) {
	e.relayMu.Lock()
	client := e.relayClient
	e.relayMu.Unlock()

	if client == nil || !client.Connected() {
		return netipAddrPort{}, false
	}
	return client.Endpoint(), true
}

// SetRelay relay klientini ulaydi.
//
// Relay ixtiyoriy: usiz ham to'g'ridan-to'g'ri yo'l ishlaydi, lekin
// symmetric NAT ortidagi peerlar bilan ulanish imkonsiz bo'ladi.
func (e *Engine) SetRelay(client *relay.Client) {
	e.relayMu.Lock()
	e.relayClient = client
	e.relayMu.Unlock()
}

// PathState — peer bilan qaysi yo'l ishlatilayotgani (diagnostika va
// `cc01 status` uchun).
func (e *Engine) PathState(key noise.PublicKey) (path.State, time.Duration, bool) {
	e.pathsMu.Lock()
	state, ok := e.paths[key]
	e.pathsMu.Unlock()

	if !ok {
		return path.StateDiscovering, 0, false
	}

	rtt, _ := state.tracker.RTT()
	return state.tracker.State(), rtt, true
}

// PeerSnapshot — peerning `cc01 peer list` uchun holati.
type PeerSnapshot struct {
	PublicKey  noise.PublicKey
	AllowedIPs []netipPrefix

	// Path — hozir ishlatilayotgan yo'l turi.
	Path path.Kind

	// State — yo'l holat mashinasidagi holat (§6.2).
	State path.State

	// Endpoint — yo'lning underlay manzili. Relay orqali bo'lsa —
	// relayning manzili.
	Endpoint netipAddrPort

	RTT time.Duration

	// Online — peer bilan sessiya bormi.
	Online bool

	// SessionAge — sessiya qancha vaqtdan beri ochiq.
	SessionAge time.Duration
}

// Snapshot barcha peerlarning holatini qaytaradi.
//
// Nusxa qaytariladi: chaqiruvchi (IPC serveri) uni tarmoqqa
// yuborishdan oldin ichki holat o'zgarib ketishi mumkin.
func (e *Engine) Snapshot() []PeerSnapshot {
	peers := e.router.Peers()
	out := make([]PeerSnapshot, 0, len(peers))

	for _, peer := range peers {
		state := e.pathFor(peer)

		kind, endpoint, _ := state.tracker.Best()
		rtt, _ := state.tracker.RTT()

		snapshot := PeerSnapshot{
			PublicKey:  peer.PublicKey,
			AllowedIPs: peer.AllowedIPs(),
			Path:       kind,
			State:      state.tracker.State(),
			Endpoint:   endpoint,
			RTT:        rtt,
		}

		if session := peer.Session(); session != nil {
			snapshot.Online = true
			snapshot.SessionAge = session.Age()
		}

		out = append(out, snapshot)
	}

	return out
}

// ListenPort — overlay UDP porti.
func (e *Engine) ListenPort() uint16 { return e.bind.Port() }

// InterfaceName — TUN interfeysi nomi.
func (e *Engine) InterfaceName() string { return e.device.Name() }
