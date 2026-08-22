package ipam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"
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

	var result *Lease

	err := a.store.Update(ctx, func(state *State) error {
		now := a.now()

		key := ownerKey{req.Kind, req.Owner, req.Parent}
		if id, ok := state.ByOwner[key]; ok {
			existing, found := state.Leases[id]
			if found && existing.State == StateActive && !existing.Expired(now) {
				// Idempotent: mavjud ijarani qaytaramiz va muddatini
				// uzaytiramiz — klient baribir qayta urinmoqda.
				existing.ExpiresAt = now.Add(LeaseTTL)
				result = existing.Clone()
				return nil
			}

			// Muddati o'tgan, lekin hali karantinga o'tkazilmagan:
			// uni shu yerda o'tkazamiz, shunda sticky ishlaydi.
			if found && existing.State == StateActive {
				existing.State = StateQuarantine
				existing.ReleasedAt = now
			}
		}

		// Sticky: agar oldingi manzil karantinda va SHU egasiga
		// tegishli bo'lsa, uni qaytarib beramiz.
		preferred, reclaimed := a.stickyCandidate(state, req)

		// Karantindagi yozuv olib tashlanadi, shunda prefiks bo'sh
		// ko'rinadi. Taqsimlash muvaffaqiyatsiz tugasa uni joyiga
		// qaytaramiz — Store xatoda avtomatik orqaga qaytarmaydi.
		if reclaimed != nil {
			state.drop(reclaimed)
		}

		prefix, err := allocatePrefix(req.Parent, req.PrefixLen, state.takenIn(req.Parent), preferred)

		// Pool to'lgandek ko'rinsa — muddati o'tgan ijaralar sababli
		// bo'lishi mumkin. Faqat SHU HOLATDA tozalab, bir marta qayta
		// urinamiz.
		//
		// Tozalash O(N): uni har bir taqsimlashda bajarish 100 000
		// tenantda taqsimlashni sekinlashtirib yuborardi.
		if errors.Is(err, ErrPoolExhausted) {
			a.sweep(state, now)
			prefix, err = allocatePrefix(req.Parent, req.PrefixLen,
				state.takenIn(req.Parent), preferred)
		}

		if err != nil {
			if reclaimed != nil {
				state.put(reclaimed)
			}
			return err
		}

		id, err := newLeaseID()
		if err != nil {
			return err
		}

		lease := &Lease{
			ID:        id,
			Prefix:    prefix,
			Kind:      req.Kind,
			State:     StateActive,
			Owner:     req.Owner,
			Tenant:    req.Tenant,
			Parent:    req.Parent,
			IssuedAt:  now,
			ExpiresAt: now.Add(LeaseTTL),
		}

		state.put(lease)
		result = lease.Clone()
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
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
	var result *Lease

	err := a.store.Update(ctx, func(state *State) error {
		now := a.now()

		lease, ok := state.Leases[leaseID]
		if !ok {
			return fmt.Errorf("%w: %s", ErrLeaseNotFound, leaseID)
		}

		// Karantindagi yoki muddati o'tgan ijarani yangilash mumkin
		// emas: klient yangi Allocate qilishi kerak.
		if lease.State != StateActive || lease.Expired(now) {
			return fmt.Errorf("%w: %s", ErrLeaseExpired, leaseID)
		}

		lease.ExpiresAt = now.Add(LeaseTTL)
		result = lease.Clone()
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// Release ijarani karantinga o'tkazadi.
//
// Prefiks DARHOL bo'shatilmaydi — QuarantinePeriod davomida ushlab
// turiladi, shunda eski marshrutlar va DNS keshi tozalanadi.
func (a *Allocator) Release(ctx context.Context, leaseID string) error {
	return a.store.Update(ctx, func(state *State) error {
		lease, ok := state.Leases[leaseID]
		if !ok {
			return fmt.Errorf("%w: %s", ErrLeaseNotFound, leaseID)
		}

		// Idempotent: qayta bo'shatish xato emas.
		if lease.State == StateQuarantine {
			return nil
		}

		lease.State = StateQuarantine
		lease.ReleasedAt = a.now()
		return nil
	})
}

// Reclaim muddati o'tgan va karantini tugagan ijaralarni tozalaydi
// va nechtasi bo'shatilganini qaytaradi.
func (a *Allocator) Reclaim(ctx context.Context) (int, error) {
	var reclaimed int

	err := a.store.Update(ctx, func(state *State) error {
		reclaimed = a.sweep(state, a.now())
		return nil
	})

	return reclaimed, err
}

// sweep — ichki tozalash: muddati o'tganlarni karantinga, karantini
// tugaganlarni butunlay o'chiradi.
func (a *Allocator) sweep(state *State, now time.Time) int {
	var reclaimed int

	for _, lease := range state.Leases {
		switch {
		case lease.State == StateActive && lease.Expired(now):
			lease.State = StateQuarantine
			lease.ReleasedAt = now

		case lease.Reclaimable(now):
			state.drop(lease)
			reclaimed++
		}
	}

	return reclaimed
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
