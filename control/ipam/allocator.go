package ipam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// ErrLeaseNotFound — bunday ijara yo'q.
	ErrLeaseNotFound = errors.New("ipam: ijara topilmadi")

	// ErrLeaseExpired — ijara muddati o'tgan, yangilab bo'lmaydi.
	ErrLeaseExpired = errors.New("ipam: ijara muddati o'tgan")

	// ErrOwnerRequired — egasi ko'rsatilmagan.
	ErrOwnerRequired = errors.New("ipam: egasi ko'rsatilmagan")
)

// Allocator — ijaralarni beradi, yangilaydi va qaytarib oladi.
type Allocator struct {
	store Store

	// now — testlarda vaqtni boshqarish uchun.
	now func() time.Time
}

// Options — allokator sozlamalari.
type Options struct {
	Store Store

	// Now — nil bo'lsa time.Now.
	Now func() time.Time
}

func New(opts Options) (*Allocator, error) {
	if opts.Store == nil {
		return nil, errors.New("ipam: store berilmagan")
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &Allocator{store: opts.Store, now: now}, nil
}

// Request — taqsimlash so'rovi.
type Request struct {
	// Kind — node manzili yoki tenant segmenti.
	Kind LeaseKind

	// Owner — node_id yoki tenant_id.
	Owner string

	// Tenant — node so'rovi uchun tenant identifikatori.
	Tenant string

	// Parent — qaysi prefiksdan ajratiladi.
	Parent netip.Prefix

	// PrefixLen — so'ralayotgan uzunlik: 128 (node), 64 yoki 56 (tenant).
	PrefixLen int

	// Preferred — oldingi manzil (sticky taqsimlash).
	Preferred netip.Prefix
}

// Allocate yangi ijara beradi.
//
// Idempotent: bir xil (Kind, Owner, Parent) uchun aktiv ijara bo'lsa,
// yangisi yaratilmaydi va mavjudi qaytariladi. Bu klientning qayta
// urinishini xavfsiz qiladi (ARCHITECTURE.md §3.1.3, qoida 3).
func (a *Allocator) Allocate(ctx context.Context, req Request) (*Lease, error) {
	if req.Owner == "" {
		return nil, ErrOwnerRequired
	}
	if err := validateChild(req.Parent, req.PrefixLen); err != nil {
		return nil, err
	}

	// Qaror LIDER tomonida qabul qilinadi, keyin to'liq aniqlangan
	// buyruq sifatida taklif qilinadi. Poyga mumkin: qaror holatning
	// nusxasi bo'yicha chiqariladi, buyruqlar esa ketma-ket
	// qo'llanadi va oradagi boshqa buyruq prefiksni band qilishi
	// mumkin. Bunday holatda qayta urinamiz.
	for attempt := range maxProposeAttempts {
		cmd, err := a.planAllocate(ctx, req)
		if err != nil {
			return nil, err
		}

		lease, _, err := a.store.Propose(ctx, cmd)
		if err == nil {
			return lease, nil
		}
		if !errors.Is(err, ErrPrefixTaken) {
			return nil, err
		}

		_ = attempt // keyingi urinishda holat qayta o'qiladi
	}

	return nil, fmt.Errorf("%w: %d urinishdan keyin ham band",
		ErrPoolExhausted, maxProposeAttempts)
}

// maxProposeAttempts — prefiks poygasida nechta marta qayta urinish.
//
// Poyga faqat ikkita taqsimlash AYNAN bir xil prefiksni tanlaganda
// yuz beradi; tasodifiy tanlov buni kam uchraydigan qiladi. Cheksiz
// urinish esa pool haqiqatan to'lganda abadiy aylanishga aylanardi.
const maxProposeAttempts = 5

// planAllocate holatni o'qib, qanday buyruq kerakligini hal qiladi.
//
// Bu YAGONA joy tasodifiy tanlov va joriy vaqt ishlatiladi. Natija —
// to'liq aniqlangan buyruq, ya'ni uni har bir replika bir xil
// qo'llaydi.
func (a *Allocator) planAllocate(ctx context.Context, req Request) (*cc01v1.LeaseCommand, error) {
	now := a.now()

	var (
		prefix    netip.Prefix
		reclaimID string
		renewID   string
	)

	err := a.store.View(ctx, func(state *State) error {
		key := ownerKey{req.Kind, req.Owner, req.Parent}
		if id, ok := state.ByOwner[key]; ok {
			existing, found := state.Leases[id]
			if found && existing.State == StateActive && !existing.Expired(now) {
				// Idempotent: mavjud ijarani uzaytiramiz — klient
				// baribir qayta urinmoqda.
				renewID = id
				return nil
			}
		}

		// Sticky: shu egasining oldingi prefiksini qaytarib beramiz.
		preferred, reclaimed := a.stickyCandidate(state, req)
		if reclaimed != nil {
			reclaimID = reclaimed.ID
		}

		// Karantindagi yozuv band ko'rinadi — uni hisobdan
		// chiqaramiz, chunki buyruq uni olib tashlaydi.
		taken := state.takenIn(req.Parent)
		if reclaimed != nil {
			filtered := make(map[netip.Prefix]struct{}, len(taken))
			for p := range taken {
				if p != reclaimed.Prefix {
					filtered[p] = struct{}{}
				}
			}
			taken = filtered
		}

		chosen, err := allocatePrefix(req.Parent, req.PrefixLen, taken, preferred)

		// Pool to'lgandek ko'rinsa — muddati o'tgan ijaralar sababli
		// bo'lishi mumkin. Faqat SHU HOLATDA tozalashni so'raymiz.
		if errors.Is(err, ErrPoolExhausted) {
			return err
		}
		if err != nil {
			return err
		}

		prefix = chosen
		return nil
	})

	// Pool to'lgan bo'lsa avval tozalash buyrug'ini taklif qilamiz,
	// keyin qayta rejalashtiramiz.
	if errors.Is(err, ErrPoolExhausted) {
		if _, err := a.Reclaim(ctx); err != nil {
			return nil, err
		}
		return a.planAllocateAfterSweep(ctx, req, now)
	}
	if err != nil {
		return nil, err
	}

	if renewID != "" {
		return renewCommand(renewID, now), nil
	}

	id, err := newLeaseID()
	if err != nil {
		return nil, err
	}

	return &cc01v1.LeaseCommand{
		Now: timestamppb.New(now),
		Command: &cc01v1.LeaseCommand_Allocate{Allocate: &cc01v1.AllocateLease{
			LeaseId:        id,
			Prefix:         prefix.String(),
			Kind:           uint32(req.Kind),
			Owner:          req.Owner,
			Tenant:         req.Tenant,
			Parent:         req.Parent.String(),
			ReclaimLeaseId: reclaimID,
			TtlSeconds:     uint64(LeaseTTL / time.Second),
		}},
	}, nil
}

// planAllocateAfterSweep tozalashdan keyin bir marta qayta
// rejalashtiradi. Ikkinchi marta pool to'lgan bo'lsa — u haqiqatan
// to'lgan.
func (a *Allocator) planAllocateAfterSweep(
	ctx context.Context,
	req Request,
	now time.Time,
) (*cc01v1.LeaseCommand, error) {
	var prefix netip.Prefix

	err := a.store.View(ctx, func(state *State) error {
		chosen, err := allocatePrefix(req.Parent, req.PrefixLen,
			state.takenIn(req.Parent), netip.Prefix{})
		if err != nil {
			return err
		}
		prefix = chosen
		return nil
	})
	if err != nil {
		return nil, err
	}

	id, err := newLeaseID()
	if err != nil {
		return nil, err
	}

	return &cc01v1.LeaseCommand{
		Now: timestamppb.New(now),
		Command: &cc01v1.LeaseCommand_Allocate{Allocate: &cc01v1.AllocateLease{
			LeaseId:    id,
			Prefix:     prefix.String(),
			Kind:       uint32(req.Kind),
			Owner:      req.Owner,
			Tenant:     req.Tenant,
			Parent:     req.Parent.String(),
			TtlSeconds: uint64(LeaseTTL / time.Second),
		}},
	}, nil
}

func renewCommand(leaseID string, now time.Time) *cc01v1.LeaseCommand {
	return &cc01v1.LeaseCommand{
		Now: timestamppb.New(now),
		Command: &cc01v1.LeaseCommand_Renew{Renew: &cc01v1.RenewLease{
			LeaseId:    leaseID,
			TtlSeconds: uint64(LeaseTTL / time.Second),
		}},
	}
}

// stickyCandidate karantindagi, lekin shu egaga tegishli prefiksni
// topadi — node qayta ulanganda IP o'zgarmasligi uchun.
//
// Holatni O'ZGARTIRMAYDI: qaytariladigan ikkinchi qiymat — olib
// tashlanishi kerak bo'lgan karantin yozuvi, uni chaqiruvchi
// taqsimlash muvaffaqiyatli bo'lgandagina saqlaydi.
func (a *Allocator) stickyCandidate(state *State, req Request) (netip.Prefix, *Lease) {
	if req.Preferred.IsValid() {
		if id, ok := state.ByPrefix[req.Preferred]; ok {
			lease := state.Leases[id]

			// Band, lekin boshqa egasiniki — sticky ishlamaydi.
			if lease != nil && lease.Owner != req.Owner {
				return netip.Prefix{}, nil
			}
			// O'ziniki va karantinda — qaytarib beramiz.
			if lease != nil && lease.State == StateQuarantine {
				return req.Preferred, lease
			}
		}
		return req.Preferred, nil
	}

	// Preferred berilmagan bo'lsa ham, shu egasining karantindagi
	// prefiksi bo'lsa uni tiklaymiz.
	key := ownerKey{req.Kind, req.Owner, req.Parent}
	if id, ok := state.ByOwner[key]; ok {
		if lease, found := state.Leases[id]; found &&
			lease.State == StateQuarantine && lease.Prefix.Bits() == req.PrefixLen {
			return lease.Prefix, lease
		}
	}

	return netip.Prefix{}, nil
}

// Renew ijara muddatini uzaytiradi.
func (a *Allocator) Renew(ctx context.Context, leaseID string) (*Lease, error) {
	lease, _, err := a.store.Propose(ctx, renewCommand(leaseID, a.now()))
	if err != nil {
		return nil, err
	}
	return lease, nil
}

// Release ijarani karantinga o'tkazadi.
//
// Prefiks DARHOL bo'shatilmaydi — QuarantinePeriod davomida ushlab
// turiladi, shunda eski marshrutlar va DNS keshi tozalanadi.
func (a *Allocator) Release(ctx context.Context, leaseID string) error {
	_, _, err := a.store.Propose(ctx, &cc01v1.LeaseCommand{
		Now: timestamppb.New(a.now()),
		Command: &cc01v1.LeaseCommand_Release{Release: &cc01v1.ReleaseLease{
			LeaseId: leaseID,
		}},
	})
	return err
}

// Reclaim muddati o'tgan va karantini tugagan ijaralarni tozalaydi
// va nechtasi bo'shatilganini qaytaradi.
func (a *Allocator) Reclaim(ctx context.Context) (int, error) {
	_, reclaimed, err := a.store.Propose(ctx, &cc01v1.LeaseCommand{
		Now:     timestamppb.New(a.now()),
		Command: &cc01v1.LeaseCommand_Sweep{Sweep: &cc01v1.SweepLeases{}},
	})
	return reclaimed, err
}

// Lease ijarani ID bo'yicha qaytaradi.
func (a *Allocator) Lease(ctx context.Context, leaseID string) (*Lease, error) {
	var result *Lease

	err := a.store.View(ctx, func(state *State) error {
		lease, ok := state.Leases[leaseID]
		if !ok {
			return fmt.Errorf("%w: %s", ErrLeaseNotFound, leaseID)
		}
		result = lease.Clone()
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Leases barcha ijaralarni qaytaradi (test va diagnostika uchun).
func (a *Allocator) Leases(ctx context.Context) ([]*Lease, error) {
	var result []*Lease

	err := a.store.View(ctx, func(state *State) error {
		result = make([]*Lease, 0, len(state.Leases))
		for _, lease := range state.Leases {
			result = append(result, lease.Clone())
		}
		return nil
	})

	return result, err
}

func newLeaseID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("ipam: ijara ID: %w", err)
	}
	return "lease_" + hex.EncodeToString(raw[:]), nil
}
