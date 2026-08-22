// Package path peer bilan qaysi yo'l orqali gaplashishni hal qiladi
// (ARCHITECTURE.md §4.1, §6.2, §6.3).
//
// Asosiy qaror — ADR-005: **relay-first, P2P-upgrade**. Ulanish darhol
// relay orqali boshlanadi (foydalanuvchi kutmaydi), to'g'ridan-to'g'ri
// yo'l esa fon rejimida sinaladi va tasdiqlangach unga o'tiladi.
//
// Teskarisi — P2P-first — har bir yangi peer bilan 2–5 soniya kutishni
// anglatardi.
package path

import (
	"fmt"
	"net/netip"
	"time"
)

// Kind — yo'l turi.
type Kind uint8

const (
	// KindNone — hali yo'l yo'q.
	KindNone Kind = iota

	// KindDirect — peer bilan to'g'ridan-to'g'ri UDP.
	KindDirect

	// KindRelay — relay tuguni orqali.
	KindRelay
)

func (k Kind) String() string {
	switch k {
	case KindDirect:
		return "direct"
	case KindRelay:
		return "relay"
	default:
		return "none"
	}
}

// State — yo'l holati (ARCHITECTURE.md §6.2 dagi holat mashinasi).
type State uint8

const (
	// StateDiscovering — hech qanday yo'l hali ishlamayapti.
	StateDiscovering State = iota

	// StateRelayActive — relay orqali ishlayapti, to'g'ridan-to'g'ri
	// yo'l nomzodi yo'q.
	StateRelayActive

	// StateProbing — relay orqali ishlayapti va shu bilan birga
	// to'g'ridan-to'g'ri yo'l fon rejimida sinalmoqda.
	StateProbing

	// StateDirectActive — to'g'ridan-to'g'ri yo'l ishlayapti.
	StateDirectActive

	// StateDegraded — to'g'ridan-to'g'ri yo'l ishlayotgan edi, lekin
	// javoblar kelmay qoldi. Hali unga yuborilmoqda, ammo o'tishga
	// tayyorlanmoqda.
	StateDegraded
)

func (s State) String() string {
	switch s {
	case StateRelayActive:
		return "relay-active"
	case StateProbing:
		return "probing"
	case StateDirectActive:
		return "direct-active"
	case StateDegraded:
		return "degraded"
	default:
		return "discovering"
	}
}

// Taymerlar va chegaralar (ARCHITECTURE.md §6.3).
const (
	// ProbeInterval — TASDIQLANGAN yo'l sifatini o'lchash davri.
	ProbeInterval = 5 * time.Second

	// InitialProbeInterval — yo'l hali tasdiqlanmagandagi davr.
	//
	// Nima uchun tezroq: tasdiqlash uchun UpgradeSamples ta o'lchov
	// kerak, ya'ni 5 soniyalik davrda foydalanuvchi ~15 soniya relayda
	// o'tirardi. Bu ADR-005 ning maqsadiga zid — relay boshlanish
	// uchun, doimiy yo'l uchun emas.
	InitialProbeInterval = 500 * time.Millisecond

	// FastProbeInterval — birinchi javobsizlikdan keyin tezroq
	// tekshiramiz, shunda uzilish tez aniqlanadi.
	FastProbeInterval = 250 * time.Millisecond

	// DegradeAfterMisses — nechta javobsizlikdan keyin yo'l
	// "shubhali" hisoblanadi. 3 × 250 ms = 750 ms.
	DegradeAfterMisses = 3

	// SwitchAfterMisses — nechta javobsizlikdan keyin relayga
	// qaytiladi. 5 × 250 ms = 1250 ms.
	SwitchAfterMisses = 5

	// UpgradeMargin — to'g'ridan-to'g'ri yo'lga o'tish uchun u
	// relaydan shuncha ulushga tez bo'lishi kerak.
	//
	// Chegara "flapping"ning oldini oladi: ikki yo'l sifati deyarli
	// teng bo'lsa, doimiy u yoqdan-bu yoqqa sakrash foyda bermaydi.
	UpgradeMargin = 0.15

	// UpgradeSamples — nechta ketma-ket o'lchov kerak. Bitta baxtli
	// o'lchov bo'yicha qaror qabul qilmaymiz.
	UpgradeSamples = 3
)

// candidate — bitta yo'l nomzodi va uning o'lchovlari.
type candidate struct {
	endpoint netip.AddrPort
	rtt      time.Duration
	lastPong time.Time
	misses   int
	valid    bool
}

func (c *candidate) String() string {
	if !c.valid {
		return "—"
	}
	return fmt.Sprintf("%v rtt=%s misses=%d", c.endpoint, c.rtt.Round(time.Microsecond), c.misses)
}
