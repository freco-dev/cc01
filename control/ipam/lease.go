// Package ipam overlay uchun IPv6 manzillarni taqsimlaydi
// (ARCHITECTURE.md §3.1.3).
//
// Ierarxiya:
//
//	2a0X:XXXX::/32        RIR bergan tashkilot prefiksi
//	  └── .../40          region (tas, eu, apac)
//	       └── .../48     PoP — BGP shu darajada e'lon qiladi
//	            └── .../64  tenant segmenti
//	                 └── .../128  node manzili
//
// Eng muhim invariant: **bir manzil ikki marta berilmaydi**. Shuning
// uchun taqsimlash bitta serializatsiyalangan tranzaksiyada bajariladi
// (Store.Update), tekshirish va yozish orasida bo'shliq qolmaydi.
package ipam

import (
	"fmt"
	"net/netip"
	"time"
)

// LeaseKind — ijara nimaga berilgani.
type LeaseKind uint8

const (
	// KindNode — bitta qurilma manzili (/128).
	KindNode LeaseKind = iota

	// KindTenant — tenant segmenti (/64 yoki /56).
	KindTenant
)

func (k LeaseKind) String() string {
	switch k {
	case KindNode:
		return "node"
	case KindTenant:
		return "tenant"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(k))
	}
}

// LeaseState — ijaraning holati (ARCHITECTURE.md §3.1.3 dagi holat
// mashinasi).
//
//	FREE ──Allocate──► ACTIVE ──renew──► ACTIVE
//	                      │ TTL o'tdi
//	                      ▼
//	                  QUARANTINE ──24h GC──► FREE
type LeaseState uint8

const (
	// StateActive — ijara amal qilmoqda.
	StateActive LeaseState = iota

	// StateQuarantine — bo'shatilgan, lekin hali qayta berilmaydi.
	//
	// Karantin kerak: eski marshrutlar, DNS keshi va peerlardagi
	// NetworkMap nusxalari tozalanmaguncha manzilni boshqa nodega
	// berish, trafikni noto'g'ri joyga yuborishga olib keladi.
	StateQuarantine
)

func (s LeaseState) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateQuarantine:
		return "quarantine"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// Muddatlar (ARCHITECTURE.md §3.1.3).
const (
	// LeaseTTL — ijara amal qilish muddati.
	LeaseTTL = 72 * time.Hour

	// RenewInterval — klient qanchalik tez-tez yangilashi kerak.
	// TTL/12: uchta ketma-ket muvaffaqiyatsiz urinishdan keyin ham
	// ancha zaxira qoladi.
	RenewInterval = LeaseTTL / 12

	// QuarantinePeriod — bo'shatilgan prefiks qancha vaqt ushlab
	// turiladi.
	QuarantinePeriod = 24 * time.Hour
)

// Lease — berilgan prefiks va uning egasi.
type Lease struct {
	ID     string
	Prefix netip.Prefix
	Kind   LeaseKind
	State  LeaseState

	// Owner — KindNode uchun node_id, KindTenant uchun tenant_id.
	Owner string

	// Tenant — node ijarasi qaysi tenantga tegishli.
	Tenant string

	// Parent — shu ijara ajratilgan ota-prefiks.
	Parent netip.Prefix

	IssuedAt  time.Time
	ExpiresAt time.Time

	// ReleasedAt — karantinga tushgan vaqt (StateQuarantine bo'lsa).
	ReleasedAt time.Time
}

// Expired — ijara muddati o'tganmi.
func (l *Lease) Expired(now time.Time) bool {
	return !l.ExpiresAt.After(now)
}

// Reclaimable — karantin tugab, prefiksni qayta berish mumkinmi.
func (l *Lease) Reclaimable(now time.Time) bool {
	return l.State == StateQuarantine &&
		!l.ReleasedAt.Add(QuarantinePeriod).After(now)
}

// Clone nusxa qaytaradi, shunda chaqiruvchi ichki holatni
// o'zgartira olmaydi.
func (l *Lease) Clone() *Lease {
	if l == nil {
		return nil
	}
	copied := *l
	return &copied
}
