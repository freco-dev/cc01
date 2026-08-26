package path

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

var (
	relayAddr  = netip.MustParseAddrPort("198.51.100.9:51820")
	directAddr = netip.MustParseAddrPort("203.0.113.7:51820")
	otherAddr  = netip.MustParseAddrPort("203.0.113.8:51820")
)

func at(seconds int) time.Time {
	return time.Date(2026, 8, 22, 12, 0, seconds, 0, time.UTC)
}

// confirmDirect to'g'ridan-to'g'ri yo'lni tasdiqlaydi: kerakli sondagi
// yetarlicha tez o'lchovlar.
func confirmDirect(t *Tracker, rtt time.Duration) {
	for i := range UpgradeSamples {
		t.RecordPong(KindDirect, rtt, at(i))
	}
}

// ═══════════════ Relay-first (ADR-005) ═══════════════

// Ulanish relaydan boshlanadi: foydalanuvchi P2P sinovini kutmasligi
// kerak.
func TestTracker_StartsOnRelay(t *testing.T) {
	tracker := NewTracker()

	if tracker.State() != StateDiscovering {
		t.Errorf("boshlang'ich holat: %v", tracker.State())
	}

	tracker.SetRelay(relayAddr, at(0))

	if tracker.State() != StateRelayActive {
		t.Errorf("relay-active kutilgan, %v olindi", tracker.State())
	}

	kind, endpoint, ok := tracker.Best()
	if !ok || kind != KindRelay || endpoint != relayAddr {
		t.Errorf("relay kutilgan, olindi: %v %v %v", kind, endpoint, ok)
	}
}

// Nomzod paydo bo'lganda ham trafik relayda qoladi — u hali
// tasdiqlanmagan.
func TestTracker_CandidateDoesNotSwitchImmediately(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.SetDirectCandidate(directAddr)

	if tracker.State() != StateProbing {
		t.Errorf("probing kutilgan, %v olindi", tracker.State())
	}

	kind, endpoint, _ := tracker.Best()
	if kind != KindRelay || endpoint != relayAddr {
		t.Errorf("hali relay kutilgan, olindi: %v %v", kind, endpoint)
	}
}

// ═══════════════ Upgrade: relay → direct ═══════════════

func TestTracker_UpgradesAfterEnoughFastSamples(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.RecordPong(KindRelay, 40*time.Millisecond, at(0))
	tracker.SetDirectCandidate(directAddr)

	// Bitta o'lchov yetarli emas.
	tracker.RecordPong(KindDirect, 5*time.Millisecond, at(1))
	if tracker.State() == StateDirectActive {
		t.Error("bitta o'lchovdan keyin o'tib ketdi")
	}

	tracker.RecordPong(KindDirect, 5*time.Millisecond, at(2))
	tracker.RecordPong(KindDirect, 5*time.Millisecond, at(3))

	if tracker.State() != StateDirectActive {
		t.Fatalf("direct-active kutilgan, %v olindi", tracker.State())
	}

	kind, endpoint, _ := tracker.Best()
	if kind != KindDirect || endpoint != directAddr {
		t.Errorf("direct kutilgan, olindi: %v %v", kind, endpoint)
	}
}

// Ikki yo'l sifati deyarli teng bo'lsa o'tish MUMKIN EMAS — aks holda
// doimiy u yoqdan-bu yoqqa sakrash boshlanadi.
func TestTracker_DoesNotUpgradeWithoutMargin(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.RecordPong(KindRelay, 10*time.Millisecond, at(0))
	tracker.SetDirectCandidate(directAddr)

	// 9 ms — 10 ms dan atigi 10% tez, chegara esa 15%.
	for i := range UpgradeSamples * 2 {
		tracker.RecordPong(KindDirect, 9*time.Millisecond, at(i))
	}

	if tracker.State() == StateDirectActive {
		t.Error("yetarli farq bo'lmasa o'tmasligi kerak")
	}
}

// Bitta baxtli o'lchov qarorni o'zgartirmasligi kerak.
func TestTracker_ResetsStreakOnSlowSample(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.RecordPong(KindRelay, 40*time.Millisecond, at(0))
	tracker.SetDirectCandidate(directAddr)

	tracker.RecordPong(KindDirect, 5*time.Millisecond, at(1))
	tracker.RecordPong(KindDirect, 5*time.Millisecond, at(2))

	// Sekin o'lchov — hisob nolga qaytadi.
	tracker.RecordPong(KindDirect, 39*time.Millisecond, at(3))

	tracker.RecordPong(KindDirect, 5*time.Millisecond, at(4))
	tracker.RecordPong(KindDirect, 5*time.Millisecond, at(5))

	if tracker.State() == StateDirectActive {
		t.Error("hisob nolga qaytishi kerak edi")
	}

	tracker.RecordPong(KindDirect, 5*time.Millisecond, at(6))
	if tracker.State() != StateDirectActive {
		t.Errorf("uchta ketma-ketdan keyin o'tishi kerak, %v olindi", tracker.State())
	}
}

// Relay hali o'lchanmagan bo'lsa taqqoslash mumkin emas — to'g'ridan-
// to'g'ri yo'l shunchaki qabul qilinadi.
func TestTracker_UpgradesWhenRelayUnmeasured(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.SetDirectCandidate(directAddr)

	confirmDirect(tracker, 20*time.Millisecond)

	if tracker.State() != StateDirectActive {
		t.Errorf("direct-active kutilgan, %v olindi", tracker.State())
	}
}

// ═══════════════ Downgrade: direct → relay ═══════════════

func TestTracker_DegradesAfterMisses(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.SetDirectCandidate(directAddr)
	confirmDirect(tracker, 5*time.Millisecond)

	for range DegradeAfterMisses - 1 {
		tracker.RecordMiss(KindDirect)
	}
	if tracker.State() != StateDirectActive {
		t.Errorf("hali direct-active bo'lishi kerak, %v olindi", tracker.State())
	}

	tracker.RecordMiss(KindDirect)
	if tracker.State() != StateDegraded {
		t.Errorf("degraded kutilgan, %v olindi", tracker.State())
	}

	// Degraded holatda ham to'g'ridan-to'g'ri yo'l ishlatiladi: erta
	// o'tish keraksiz uzilishlarga olib keladi.
	kind, _, _ := tracker.Best()
	if kind != KindDirect {
		t.Errorf("degraded holatda direct kutilgan, %v olindi", kind)
	}
}

func TestTracker_SwitchesToRelayAfterEnoughMisses(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.SetDirectCandidate(directAddr)
	confirmDirect(tracker, 5*time.Millisecond)

	for range SwitchAfterMisses {
		tracker.RecordMiss(KindDirect)
	}

	kind, endpoint, ok := tracker.Best()
	if !ok || kind != KindRelay || endpoint != relayAddr {
		t.Errorf("relayga qaytish kutilgan, olindi: %v %v", kind, endpoint)
	}
	if tracker.State() != StateProbing {
		t.Errorf("probing kutilgan, %v olindi", tracker.State())
	}
}

// Javob tiklansa darhol qaytishi kerak — bu qisqa uzilishlar uchun.
func TestTracker_RecoversFromDegraded(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.SetDirectCandidate(directAddr)
	confirmDirect(tracker, 5*time.Millisecond)

	for range DegradeAfterMisses {
		tracker.RecordMiss(KindDirect)
	}
	if tracker.State() != StateDegraded {
		t.Fatalf("degraded kutilgan, %v olindi", tracker.State())
	}

	tracker.RecordPong(KindDirect, 5*time.Millisecond, at(10))

	if tracker.State() != StateDirectActive {
		t.Errorf("tiklanish kutilgan, %v olindi", tracker.State())
	}
}

// Relay ham yo'q bo'lsa boshqa tanlov qolmaydi.
func TestTracker_FallsBackToDiscoveringWithoutRelay(t *testing.T) {
	tracker := NewTracker()
	tracker.SetDirectCandidate(directAddr)
	confirmDirect(tracker, 5*time.Millisecond)

	for range SwitchAfterMisses {
		tracker.RecordMiss(KindDirect)
	}

	if tracker.State() != StateDiscovering {
		t.Errorf("discovering kutilgan, %v olindi", tracker.State())
	}
}

// ═══════════════ Probe tezligi ═══════════════

// Javobsizlik boshlanganda tezroq tekshirish kerak: uzilishni 5
// soniyada emas, bir necha yuz millisekundda aniqlash kerak.
func TestTracker_ProbeIntervalSpeedsUpOnMiss(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.SetDirectCandidate(directAddr)
	confirmDirect(tracker, 5*time.Millisecond)

	if got := tracker.ProbeInterval(); got != ProbeInterval {
		t.Errorf("%s kutilgan, %s olindi", ProbeInterval, got)
	}

	tracker.RecordMiss(KindDirect)

	if got := tracker.ProbeInterval(); got != FastProbeInterval {
		t.Errorf("%s kutilgan, %s olindi", FastProbeInterval, got)
	}

	tracker.RecordPong(KindDirect, 5*time.Millisecond, at(1))

	if got := tracker.ProbeInterval(); got != ProbeInterval {
		t.Errorf("tiklangach %s kutilgan, %s olindi", ProbeInterval, got)
	}
}

// ═══════════════ Nomzod almashishi ═══════════════

// Peer manzilini o'zgartirsa (roaming), o'lchovlar noldan
// boshlanishi kerak — eski o'lchovlar yangi yo'lga taalluqli emas.
func TestTracker_NewCandidateResetsMeasurements(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.RecordPong(KindRelay, 40*time.Millisecond, at(0))
	tracker.SetDirectCandidate(directAddr)
	confirmDirect(tracker, 5*time.Millisecond)

	if tracker.State() != StateDirectActive {
		t.Fatalf("direct-active kutilgan, %v olindi", tracker.State())
	}

	tracker.SetDirectCandidate(otherAddr)

	// Yangi nomzod tasdiqlanmagan — trafik relayga qaytadi.
	kind, endpoint, _ := tracker.Best()
	if kind != KindRelay {
		t.Errorf("relay kutilgan, olindi: %v %v", kind, endpoint)
	}

	if candidate, ok := tracker.DirectCandidate(); !ok || candidate != otherAddr {
		t.Errorf("yangi nomzod kutilgan, olindi: %v", candidate)
	}
}

func TestTracker_SameCandidateKeepsMeasurements(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.SetDirectCandidate(directAddr)
	confirmDirect(tracker, 5*time.Millisecond)

	tracker.SetDirectCandidate(directAddr)

	if tracker.State() != StateDirectActive {
		t.Errorf("o'sha nomzod holatni buzmasligi kerak, %v olindi", tracker.State())
	}
}

// ═══════════════ Yordamchilar ═══════════════

func TestTracker_NoPathAtAll(t *testing.T) {
	tracker := NewTracker()

	if _, _, ok := tracker.Best(); ok {
		t.Error("yo'l yo'q bo'lishi kerak edi")
	}
	if _, ok := tracker.RTT(); ok {
		t.Error("RTT bo'lmasligi kerak")
	}
}

func TestTracker_ReportsRTTOfActivePath(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.RecordPong(KindRelay, 40*time.Millisecond, at(0))

	if rtt, ok := tracker.RTT(); !ok || rtt != 40*time.Millisecond {
		t.Errorf("relay RTT kutilgan, olindi: %v %v", rtt, ok)
	}

	tracker.SetDirectCandidate(directAddr)
	confirmDirect(tracker, 5*time.Millisecond)

	if rtt, ok := tracker.RTT(); !ok || rtt != 5*time.Millisecond {
		t.Errorf("direct RTT kutilgan, olindi: %v %v", rtt, ok)
	}
}

func TestTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.SetDirectCandidate(directAddr)

	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := range 1000 {
			tracker.RecordPong(KindDirect, time.Duration(i)*time.Microsecond, at(i))
			tracker.RecordMiss(KindRelay)
		}
	}()

	for range 1000 {
		tracker.Best()
		tracker.State()
		tracker.ProbeInterval()
		tracker.Describe()
	}

	<-done
}

// ═══════════════ Disco xabari ═══════════════

func TestDisco_RoundTrip(t *testing.T) {
	nonce, err := NewNonce()
	if err != nil {
		t.Fatalf("NewNonce: %v", err)
	}

	for _, kind := range []DiscoKind{Ping, Pong} {
		payload := EncodeDisco(kind, nonce)
		if len(payload) != DiscoSize {
			t.Fatalf("uzunlik %d, kutilgan %d", len(payload), DiscoSize)
		}

		gotKind, gotNonce, err := DecodeDisco(payload)
		if err != nil {
			t.Fatalf("DecodeDisco(%v): %v", kind, err)
		}
		if gotKind != kind {
			t.Errorf("%v kutilgan, %v olindi", kind, gotKind)
		}
		if gotNonce != nonce {
			t.Errorf("nonce %d kutilgan, %d olindi", nonce, gotNonce)
		}
	}
}

func TestDisco_RejectsBadInput(t *testing.T) {
	cases := [][]byte{
		nil,
		make([]byte, DiscoSize-1),
		make([]byte, DiscoSize+1),
		append([]byte{0xff}, make([]byte, 8)...), // noma'lum tur
	}

	for i, payload := range cases {
		if _, _, err := DecodeDisco(payload); !errors.Is(err, ErrBadDisco) {
			t.Errorf("holat %d: ErrBadDisco kutilgan, olindi: %v", i, err)
		}
	}
}

func TestNewNonce_IsRandom(t *testing.T) {
	seen := make(map[uint64]bool, 100)

	for range 100 {
		nonce, err := NewNonce()
		if err != nil {
			t.Fatalf("NewNonce: %v", err)
		}
		if seen[nonce] {
			t.Fatalf("nonce takrorlandi: %d", nonce)
		}
		seen[nonce] = true
	}
}

// Tasdiqlanmagan yo'l tezroq sinaladi: aks holda foydalanuvchi
// UpgradeSamples × ProbeInterval = ~15 soniya relayda o'tirardi.
func TestTracker_ProbesFasterBeforeConfirmation(t *testing.T) {
	tracker := NewTracker()
	tracker.SetRelay(relayAddr, at(0))
	tracker.SetDirectCandidate(directAddr)

	if got := tracker.ProbeInterval(); got != InitialProbeInterval {
		t.Errorf("tasdiqlashdan oldin %s kutilgan, %s olindi", InitialProbeInterval, got)
	}

	confirmDirect(tracker, 5*time.Millisecond)

	if got := tracker.ProbeInterval(); got != ProbeInterval {
		t.Errorf("tasdiqlangach %s kutilgan, %s olindi", ProbeInterval, got)
	}
}
