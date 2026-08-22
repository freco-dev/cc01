package path

import (
	"net/netip"
	"sync"
	"time"
)

// Tracker — bitta peer uchun yo'l holati.
//
// Bir vaqtda bir nechta goroutine ishlatishi mumkin: datapath yo'lni
// o'qiydi, probe goroutine esa o'lchovlarni yozadi.
type Tracker struct {
	mu sync.Mutex

	direct candidate
	relay  candidate

	// upgradeStreak — to'g'ridan-to'g'ri yo'l ketma-ket necha marta
	// relaydan sezilarli tez chiqdi.
	upgradeStreak int

	state State
}

func NewTracker() *Tracker {
	return &Tracker{state: StateDiscovering}
}

// SetRelay relay yo'lini o'rnatadi.
//
// Relay ishlashi ma'lum bo'lgani uchun u darhol faol hisoblanadi —
// ADR-005: ulanish relaydan boshlanadi.
func (t *Tracker) SetRelay(endpoint netip.AddrPort, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// O'sha relay qayta berilsa o'lchovlarni SAQLAB QOLAMIZ — aks
	// holda har bir yangilanish RTT tarixini o'chirib yuborardi.
	if t.relay.valid && t.relay.endpoint == endpoint {
		return
	}

	t.relay = candidate{endpoint: endpoint, lastPong: now, valid: true}

	if t.state == StateDiscovering {
		t.state = StateRelayActive
	}
}

// SetDirectCandidate to'g'ridan-to'g'ri yo'l nomzodini beradi.
//
// Nomzod hali TASDIQLANMAGAN: unga o'tish uchun probe javobi kerak.
func (t *Tracker) SetDirectCandidate(endpoint netip.AddrPort) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.direct.valid && t.direct.endpoint == endpoint {
		return
	}

	// Yangi nomzod — o'lchovlar noldan boshlanadi.
	t.direct = candidate{endpoint: endpoint}
	t.upgradeStreak = 0

	if t.state == StateRelayActive {
		t.state = StateProbing
	}
}

// RecordPong probe javobini qayd etadi.
func (t *Tracker) RecordPong(kind Kind, rtt time.Duration, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch kind {
	case KindRelay:
		t.relay.rtt = rtt
		t.relay.lastPong = now
		t.relay.misses = 0
		t.relay.valid = true

	case KindDirect:
		t.direct.rtt = rtt
		t.direct.lastPong = now
		t.direct.misses = 0
		t.direct.valid = true

		t.evaluateUpgradeLocked()
	}
}

// RecordMiss probe javobsiz qolganini qayd etadi.
func (t *Tracker) RecordMiss(kind Kind) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch kind {
	case KindRelay:
		t.relay.misses++

	case KindDirect:
		t.direct.misses++
		t.evaluateDowngradeLocked()
	}
}

// evaluateUpgradeLocked to'g'ridan-to'g'ri yo'lga o'tish kerakmi,
// shuni hal qiladi.
func (t *Tracker) evaluateUpgradeLocked() {
	// Degraded holatdan qaytish: javob tiklandi.
	if t.state == StateDegraded {
		t.state = StateDirectActive
		return
	}

	if t.state == StateDirectActive {
		return
	}

	// Relay o'lchanmagan bo'lsa taqqoslay olmaymiz — to'g'ridan-to'g'ri
	// yo'lni shunchaki qabul qilamiz, u relaydan yomon bo'lishi
	// dargumon.
	if !t.relay.valid || t.relay.rtt == 0 {
		t.upgradeStreak++
	} else if float64(t.direct.rtt) <= float64(t.relay.rtt)*(1-UpgradeMargin) {
		t.upgradeStreak++
	} else {
		// Sezilarli tez emas — hisobni nolga qaytaramiz.
		t.upgradeStreak = 0
		return
	}

	if t.upgradeStreak >= UpgradeSamples {
		t.state = StateDirectActive
	}
}

// evaluateDowngradeLocked javobsizliklar bo'yicha holatni tushiradi.
func (t *Tracker) evaluateDowngradeLocked() {
	if t.state != StateDirectActive && t.state != StateDegraded {
		return
	}

	switch {
	case t.direct.misses >= SwitchAfterMisses:
		// Yo'l uzildi — relayga qaytamiz.
		t.direct.valid = false
		t.upgradeStreak = 0
		if t.relay.valid {
			t.state = StateProbing
		} else {
			t.state = StateDiscovering
		}

	case t.direct.misses >= DegradeAfterMisses:
		t.state = StateDegraded
	}
}

// Best hozir ishlatilishi kerak bo'lgan yo'lni qaytaradi.
//
// Degraded holatda ham to'g'ridan-to'g'ri yo'l ishlatiladi: u hali
// butunlay uzilmagan bo'lishi mumkin, va erta o'tish keraksiz
// uzilishlarga olib keladi.
func (t *Tracker) Best() (Kind, netip.AddrPort, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch t.state {
	case StateDirectActive, StateDegraded:
		if t.direct.valid {
			return KindDirect, t.direct.endpoint, true
		}
	}

	if t.relay.valid {
		return KindRelay, t.relay.endpoint, true
	}

	// Relay yo'q, lekin to'g'ridan-to'g'ri nomzod bor — boshqa
	// tanlov qolmadi.
	if t.direct.endpoint.IsValid() {
		return KindDirect, t.direct.endpoint, true
	}

	return KindNone, netip.AddrPort{}, false
}

// State — joriy holat.
func (t *Tracker) State() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// DirectCandidate — sinalayotgan to'g'ridan-to'g'ri manzil.
func (t *Tracker) DirectCandidate() (netip.AddrPort, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.direct.endpoint.IsValid() {
		return netip.AddrPort{}, false
	}
	return t.direct.endpoint, true
}

// RelayEndpoint — relay manzili.
func (t *Tracker) RelayEndpoint() (netip.AddrPort, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.relay.valid {
		return netip.AddrPort{}, false
	}
	return t.relay.endpoint, true
}

// ProbeInterval — hozir qanchalik tez-tez tekshirish kerak.
//
// Javobsizlik boshlanganda tezlashamiz: uzilishni 5 soniyada emas,
// bir necha yuz millisekundda aniqlash kerak.
func (t *Tracker) ProbeInterval() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Javobsizlik boshlangan — uzilishni tez aniqlash kerak.
	if t.direct.misses > 0 || t.state == StateDegraded {
		return FastProbeInterval
	}

	// Yo'l hali tasdiqlanmagan — uni tezroq sinaymiz, shunda relayda
	// o'tirish vaqti qisqaradi.
	if t.state != StateDirectActive {
		return InitialProbeInterval
	}

	return ProbeInterval
}

// RTT — joriy yo'lning o'lchangan kechikishi.
func (t *Tracker) RTT() (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch t.state {
	case StateDirectActive, StateDegraded:
		if t.direct.valid {
			return t.direct.rtt, true
		}
	}
	if t.relay.valid && t.relay.rtt > 0 {
		return t.relay.rtt, true
	}
	return 0, false
}

// Describe — diagnostika uchun qisqa tavsif.
func (t *Tracker) Describe() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return "state=" + t.state.String() +
		" direct=" + t.direct.String() +
		" relay=" + t.relay.String()
}
