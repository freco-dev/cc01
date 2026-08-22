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
func (e *Engine) forgetPath(key noise.PublicKey) {
	e.pathsMu.Lock()
	defer e.pathsMu.Unlock()
	delete(e.paths, key)
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
