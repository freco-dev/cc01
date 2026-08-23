package ipam

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// Holat mashinasi: buyruqni holatga qo'llash.
//
// Bu funksiyalar SOF va DETERMINISTIK bo'lishi shart — ular Raft
// jurnalidagi har bir yozuv uchun HAR BIR replikada bajariladi va
// natija bir xil chiqishi kerak. Shuning uchun ular ichida:
//
//   - joriy vaqt o'qilmaydi (buyruqdagi `now` ishlatiladi)
//   - tasodifiy son olinmaydi (prefiks va ID liderdan keladi)
//   - konstantalarga tayanilmaydi (TTL ham buyruqda)
//
// Oxirgisi nozik: konstanta o'zgargandan keyin eski jurnal qayta
// o'qilsa, u boshqacha qo'llanib replikalarni ajratib yuborardi.

var (
	// ErrPrefixTaken — lider tanlagan prefiks u yozguncha band
	// bo'lib qolgan.
	//
	// Bu normal poyga: lider qarorni holatning nusxasi bo'yicha
	// qabul qiladi, jurnal esa buyruqlarni ketma-ket qo'llaydi.
	// Taklif qiluvchi qayta urinadi.
	ErrPrefixTaken = errors.New("ipam: prefiks band")

	// ErrBadCommand — buyruq buzuq yoki noma'lum.
	ErrBadCommand = errors.New("ipam: buyruq yaroqsiz")
)

// Apply buyruqni holatga qo'llaydi.
//
// Qaytarilgan ijara — nusxa; chaqiruvchi uni erkin o'zgartirishi
// mumkin. Sweep uchun nil qaytadi va `count` to'ldiriladi.
func (s *State) Apply(cmd *cc01v1.LeaseCommand) (*Lease, int, error) {
	if cmd == nil {
		return nil, 0, fmt.Errorf("%w: bo'sh", ErrBadCommand)
	}

	now := cmd.GetNow().AsTime()

	switch body := cmd.GetCommand().(type) {
	case *cc01v1.LeaseCommand_Allocate:
		lease, err := s.applyAllocate(body.Allocate, now)
		return lease, 0, err

	case *cc01v1.LeaseCommand_Renew:
		lease, err := s.applyRenew(body.Renew, now)
		return lease, 0, err

	case *cc01v1.LeaseCommand_Release:
		return nil, 0, s.applyRelease(body.Release, now)

	case *cc01v1.LeaseCommand_Sweep:
		return nil, s.Sweep(now), nil

	default:
		return nil, 0, fmt.Errorf("%w: turi noma'lum", ErrBadCommand)
	}
}

func (s *State) applyAllocate(cmd *cc01v1.AllocateLease, now time.Time) (*Lease, error) {
	prefix, err := netip.ParsePrefix(cmd.GetPrefix())
	if err != nil {
		return nil, fmt.Errorf("%w: prefiks (%s): %v", ErrBadCommand, cmd.GetPrefix(), err)
	}
	parent, err := netip.ParsePrefix(cmd.GetParent())
	if err != nil {
		return nil, fmt.Errorf("%w: ota-prefiks (%s): %v", ErrBadCommand, cmd.GetParent(), err)
	}
	if cmd.GetLeaseId() == "" {
		return nil, fmt.Errorf("%w: ijara ID'si yo'q", ErrBadCommand)
	}

	// Sticky: lider olib tashlanishi kerak bo'lgan karantin yozuvini
	// ko'rsatgan bo'lsa, uni AVVAL olib tashlaymiz — aks holda o'sha
	// prefiks band ko'rinadi.
	if id := cmd.GetReclaimLeaseId(); id != "" {
		if lease, ok := s.Leases[id]; ok {
			s.drop(lease)
		}
	}

	// Idempotentlik tekshiruvi bandlik tekshiruvidan OLDIN turishi
	// shart. Aks holda takroriy buyruq O'ZINING ijarasini "band" deb
	// ko'rib, ErrPrefixTaken qaytarardi — va taklif qiluvchi allaqachon
	// bajarilgan ishni qayta urinib, boshqa prefiks olardi.
	if existing, ok := s.Leases[cmd.GetLeaseId()]; ok {
		return existing.Clone(), nil
	}

	// Poyga tekshiruvi: lider qaror qabul qilgandan keyin, buyruq
	// jurnalda navbat kutayotgan paytda boshqa buyruq shu prefiksni
	// band qilgan bo'lishi mumkin.
	if id, taken := s.ByPrefix[prefix]; taken {
		return nil, fmt.Errorf("%w: %s (%s)", ErrPrefixTaken, prefix, id)
	}

	ttl := time.Duration(cmd.GetTtlSeconds()) * time.Second

	lease := &Lease{
		ID:        cmd.GetLeaseId(),
		Prefix:    prefix,
		Kind:      LeaseKind(cmd.GetKind()),
		State:     StateActive,
		Owner:     cmd.GetOwner(),
		Tenant:    cmd.GetTenant(),
		Parent:    parent,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}

	s.put(lease)
	return lease.Clone(), nil
}

func (s *State) applyRenew(cmd *cc01v1.RenewLease, now time.Time) (*Lease, error) {
	lease, ok := s.Leases[cmd.GetLeaseId()]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrLeaseNotFound, cmd.GetLeaseId())
	}

	// Karantindagi yoki muddati o'tgan ijarani yangilash mumkin emas:
	// klient yangi Allocate qilishi kerak.
	if lease.State != StateActive || lease.Expired(now) {
		return nil, fmt.Errorf("%w: %s", ErrLeaseExpired, cmd.GetLeaseId())
	}

	lease.ExpiresAt = now.Add(time.Duration(cmd.GetTtlSeconds()) * time.Second)
	return lease.Clone(), nil
}

func (s *State) applyRelease(cmd *cc01v1.ReleaseLease, now time.Time) error {
	lease, ok := s.Leases[cmd.GetLeaseId()]
	if !ok {
		return fmt.Errorf("%w: %s", ErrLeaseNotFound, cmd.GetLeaseId())
	}

	// Idempotent: qayta bo'shatish xato emas.
	if lease.State == StateQuarantine {
		return nil
	}

	lease.State = StateQuarantine
	lease.ReleasedAt = now
	return nil
}

// Sweep muddati o'tganlarni karantinga o'tkazadi, karantini
// tugaganlarni butunlay o'chiradi va nechtasi bo'shatilganini
// qaytaradi.
//
// Xarita bo'ylab yurish tartibi Go'da tasodifiy, lekin natija undan
// bog'liq emas: har bir ijara mustaqil ravishda qayta ishlanadi.
func (s *State) Sweep(now time.Time) int {
	var reclaimed int

	for _, lease := range s.Leases {
		switch {
		case lease.State == StateActive && lease.Expired(now):
			lease.State = StateQuarantine
			lease.ReleasedAt = now

		case lease.Reclaimable(now):
			s.drop(lease)
			reclaimed++
		}
	}

	return reclaimed
}
