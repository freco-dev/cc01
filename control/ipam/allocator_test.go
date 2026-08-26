package ipam

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// clock — testlarda vaqtni boshqarish uchun.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newAllocator(t *testing.T) (*Allocator, *clock) {
	t.Helper()

	c := newClock()
	allocator, err := New(Options{Store: NewMemoryStore(), Now: c.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return allocator, c
}

const (
	tenantNet = "2a0e:1234:1::/64" // node manzillari shu yerdan
	popNet    = "2a0e:1234::/48"   // tenant segmentlari shu yerdan
)

func nodeRequest(owner string) Request {
	return Request{
		Kind:      KindNode,
		Owner:     owner,
		Tenant:    "t_demo",
		Parent:    netip.MustParsePrefix(tenantNet),
		PrefixLen: 128,
	}
}

func TestAllocate_ReturnsAddressInsideParent(t *testing.T) {
	allocator, _ := newAllocator(t)
	parent := netip.MustParsePrefix(tenantNet)

	lease, err := allocator.Allocate(t.Context(), nodeRequest("node-1"))
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	if lease.Prefix.Bits() != 128 {
		t.Errorf("/128 kutilgan, /%d olindi", lease.Prefix.Bits())
	}
	if !parent.Contains(lease.Prefix.Addr()) {
		t.Errorf("%v ota-prefiks %v ichida emas", lease.Prefix, parent)
	}
	if lease.State != StateActive {
		t.Errorf("holat: %v", lease.State)
	}
	if lease.Owner != "node-1" {
		t.Errorf("egasi: %q", lease.Owner)
	}
}

// Qabul mezoni: 1000 node, double-allocation 0.
func TestAllocate_NoDoubleAllocation(t *testing.T) {
	allocator, _ := newAllocator(t)

	const nodes = 1000
	seen := make(map[netip.Prefix]string, nodes)

	for i := range nodes {
		owner := fmt.Sprintf("node-%d", i)

		lease, err := allocator.Allocate(t.Context(), nodeRequest(owner))
		if err != nil {
			t.Fatalf("Allocate(%s): %v", owner, err)
		}

		if previous, clash := seen[lease.Prefix]; clash {
			t.Fatalf("IKKI MARTA TAQSIMLANDI: %v — %s va %s",
				lease.Prefix, previous, owner)
		}
		seen[lease.Prefix] = owner
	}

	if len(seen) != nodes {
		t.Errorf("%d noyob manzil kutilgan, %d olindi", nodes, len(seen))
	}
}

// Parallel taqsimlash ham to'qnashuvsiz bo'lishi kerak — Store
// serializatsiyasi aynan shu uchun.
func TestAllocate_ConcurrentIsSafe(t *testing.T) {
	allocator, _ := newAllocator(t)

	const workers, perWorker = 16, 40

	var (
		mu   sync.Mutex
		seen = make(map[netip.Prefix]string, workers*perWorker)
		wg   sync.WaitGroup
	)

	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for i := range perWorker {
				owner := fmt.Sprintf("w%d-n%d", worker, i)

				lease, err := allocator.Allocate(context.Background(), nodeRequest(owner))
				if err != nil {
					t.Errorf("Allocate(%s): %v", owner, err)
					return
				}

				mu.Lock()
				if previous, clash := seen[lease.Prefix]; clash {
					t.Errorf("IKKI MARTA TAQSIMLANDI: %v — %s va %s",
						lease.Prefix, previous, owner)
				}
				seen[lease.Prefix] = owner
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != workers*perWorker {
		t.Errorf("%d noyob manzil kutilgan, %d olindi", workers*perWorker, len(seen))
	}
}

// Klient qayta urinishi xavfsiz bo'lishi kerak: bir xil so'rov bir xil
// natija beradi (ARCHITECTURE.md §3.1.3, qoida 3).
func TestAllocate_IsIdempotent(t *testing.T) {
	allocator, _ := newAllocator(t)

	first, err := allocator.Allocate(t.Context(), nodeRequest("node-1"))
	if err != nil {
		t.Fatalf("birinchi Allocate: %v", err)
	}

	second, err := allocator.Allocate(t.Context(), nodeRequest("node-1"))
	if err != nil {
		t.Fatalf("ikkinchi Allocate: %v", err)
	}

	if first.Prefix != second.Prefix {
		t.Errorf("bir xil manzil kutilgan: %v va %v", first.Prefix, second.Prefix)
	}
	if first.ID != second.ID {
		t.Errorf("bir xil ijara kutilgan: %s va %s", first.ID, second.ID)
	}

	leases, _ := allocator.Leases(t.Context())
	if len(leases) != 1 {
		t.Errorf("bitta ijara kutilgan, %d olindi", len(leases))
	}
}

func TestAllocate_StickyReturnsPreferredAddress(t *testing.T) {
	allocator, _ := newAllocator(t)

	preferred := netip.MustParsePrefix("2a0e:1234:1::b7f2/128")

	request := nodeRequest("node-1")
	request.Preferred = preferred

	lease, err := allocator.Allocate(t.Context(), request)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	if lease.Prefix != preferred {
		t.Errorf("%v kutilgan, %v olindi", preferred, lease.Prefix)
	}
}

// Boshqa node band qilgan manzilni sticky orqali tortib olib bo'lmaydi.
func TestAllocate_PreferredTakenByAnotherOwnerIsIgnored(t *testing.T) {
	allocator, _ := newAllocator(t)

	preferred := netip.MustParsePrefix("2a0e:1234:1::b7f2/128")

	first := nodeRequest("node-1")
	first.Preferred = preferred
	if _, err := allocator.Allocate(t.Context(), first); err != nil {
		t.Fatalf("birinchi: %v", err)
	}

	second := nodeRequest("node-2")
	second.Preferred = preferred
	lease, err := allocator.Allocate(t.Context(), second)
	if err != nil {
		t.Fatalf("ikkinchi: %v", err)
	}

	if lease.Prefix == preferred {
		t.Error("band manzil boshqa egaga berildi")
	}
}

// Qayta ulangan node o'z manzilini qaytarib olishi kerak — IP
// o'zgarishi minimallashtiriladi.
func TestAllocate_StickyRecoversFromQuarantine(t *testing.T) {
	allocator, _ := newAllocator(t)

	first, err := allocator.Allocate(t.Context(), nodeRequest("node-1"))
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	if err := allocator.Release(t.Context(), first.ID); err != nil {
		t.Fatalf("Release: %v", err)
	}

	request := nodeRequest("node-1")
	request.Preferred = first.Prefix

	second, err := allocator.Allocate(t.Context(), request)
	if err != nil {
		t.Fatalf("qayta Allocate: %v", err)
	}

	if second.Prefix != first.Prefix {
		t.Errorf("o'sha manzil kutilgan: %v, olindi %v", first.Prefix, second.Prefix)
	}
}

// ═══════════════ Ijara hayot sikli ═══════════════

func TestRenew_ExtendsExpiry(t *testing.T) {
	allocator, c := newAllocator(t)

	lease, err := allocator.Allocate(t.Context(), nodeRequest("node-1"))
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	original := lease.ExpiresAt

	c.advance(RenewInterval)

	renewed, err := allocator.Renew(t.Context(), lease.ID)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}

	if !renewed.ExpiresAt.After(original) {
		t.Errorf("muddat uzaymadi: %v → %v", original, renewed.ExpiresAt)
	}
	if renewed.Prefix != lease.Prefix {
		t.Error("yangilashda manzil o'zgardi")
	}
}

func TestRenew_RejectsUnknownLease(t *testing.T) {
	allocator, _ := newAllocator(t)

	if _, err := allocator.Renew(t.Context(), "lease_yoq"); !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("ErrLeaseNotFound kutilgan, olindi: %v", err)
	}
}

func TestRenew_RejectsExpiredLease(t *testing.T) {
	allocator, c := newAllocator(t)

	lease, err := allocator.Allocate(t.Context(), nodeRequest("node-1"))
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	c.advance(LeaseTTL + time.Minute)

	if _, err := allocator.Renew(t.Context(), lease.ID); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("ErrLeaseExpired kutilgan, olindi: %v", err)
	}
}

// Bo'shatilgan prefiks DARHOL qayta berilmasligi kerak: eski
// marshrutlar va DNS keshi tozalanishi uchun karantin bor.
func TestRelease_PutsPrefixInQuarantine(t *testing.T) {
	allocator, _ := newAllocator(t)

	lease, err := allocator.Allocate(t.Context(), nodeRequest("node-1"))
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	if err := allocator.Release(t.Context(), lease.ID); err != nil {
		t.Fatalf("Release: %v", err)
	}

	after, err := allocator.Lease(t.Context(), lease.ID)
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if after.State != StateQuarantine {
		t.Errorf("karantin kutilgan, %v olindi", after.State)
	}

	// Boshqa node shu manzilni ololmasligi kerak.
	request := nodeRequest("node-2")
	request.Preferred = lease.Prefix

	other, err := allocator.Allocate(t.Context(), request)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if other.Prefix == lease.Prefix {
		t.Error("karantindagi manzil boshqa nodega berildi")
	}
}

func TestRelease_IsIdempotent(t *testing.T) {
	allocator, _ := newAllocator(t)

	lease, _ := allocator.Allocate(t.Context(), nodeRequest("node-1"))

	if err := allocator.Release(t.Context(), lease.ID); err != nil {
		t.Fatalf("birinchi Release: %v", err)
	}
	if err := allocator.Release(t.Context(), lease.ID); err != nil {
		t.Errorf("ikkinchi Release: %v", err)
	}
}

func TestReclaim_FreesPrefixAfterQuarantine(t *testing.T) {
	allocator, c := newAllocator(t)

	lease, _ := allocator.Allocate(t.Context(), nodeRequest("node-1"))
	if err := allocator.Release(t.Context(), lease.ID); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// Karantin hali tugamagan.
	reclaimed, err := allocator.Reclaim(t.Context())
	if err != nil {
		t.Fatalf("Reclaim: %v", err)
	}
	if reclaimed != 0 {
		t.Errorf("erta bo'shatildi: %d", reclaimed)
	}

	c.advance(QuarantinePeriod + time.Minute)

	reclaimed, err = allocator.Reclaim(t.Context())
	if err != nil {
		t.Fatalf("Reclaim: %v", err)
	}
	if reclaimed != 1 {
		t.Errorf("1 ta bo'shatilishi kerak edi, %d olindi", reclaimed)
	}

	// Endi manzilni boshqa node olishi mumkin.
	request := nodeRequest("node-2")
	request.Preferred = lease.Prefix

	other, err := allocator.Allocate(t.Context(), request)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if other.Prefix != lease.Prefix {
		t.Errorf("bo'shagan manzil kutilgan %v, olindi %v", lease.Prefix, other.Prefix)
	}
}

// Yangilanmagan ijara muddati o'tgach avtomatik karantinga tushadi.
func TestExpiredLeaseMovesToQuarantine(t *testing.T) {
	allocator, c := newAllocator(t)

	lease, _ := allocator.Allocate(t.Context(), nodeRequest("node-1"))

	c.advance(LeaseTTL + time.Minute)
	if _, err := allocator.Reclaim(t.Context()); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}

	after, err := allocator.Lease(t.Context(), lease.ID)
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if after.State != StateQuarantine {
		t.Errorf("karantin kutilgan, %v olindi", after.State)
	}
}

// ═══════════════ Tenant segmentlari ═══════════════

func TestAllocate_TenantSegments(t *testing.T) {
	allocator, _ := newAllocator(t)
	pop := netip.MustParsePrefix(popNet)

	seen := make(map[netip.Prefix]bool)

	for i := range 50 {
		lease, err := allocator.Allocate(t.Context(), Request{
			Kind:      KindTenant,
			Owner:     fmt.Sprintf("t_%d", i),
			Parent:    pop,
			PrefixLen: 64,
		})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}

		if lease.Prefix.Bits() != 64 {
			t.Errorf("/64 kutilgan, /%d olindi", lease.Prefix.Bits())
		}
		if !pop.Contains(lease.Prefix.Addr()) {
			t.Errorf("%v PoP prefiksi ichida emas", lease.Prefix)
		}
		if seen[lease.Prefix] {
			t.Fatalf("IKKI MARTA TAQSIMLANDI: %v", lease.Prefix)
		}
		seen[lease.Prefix] = true
	}
}

// Node va tenant ijaralari bir-biriga xalaqit qilmasligi kerak.
func TestAllocate_KindsAreIndependent(t *testing.T) {
	allocator, _ := newAllocator(t)

	node, err := allocator.Allocate(t.Context(), nodeRequest("shared-id"))
	if err != nil {
		t.Fatalf("node: %v", err)
	}

	tenant, err := allocator.Allocate(t.Context(), Request{
		Kind:      KindTenant,
		Owner:     "shared-id",
		Parent:    netip.MustParsePrefix(popNet),
		PrefixLen: 64,
	})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}

	if node.ID == tenant.ID {
		t.Error("bir xil ijara qaytarildi")
	}
	if node.Kind == tenant.Kind {
		t.Error("turlar ajratilmadi")
	}
}

// ═══════════════ Validatsiya ═══════════════

func TestAllocate_Validation(t *testing.T) {
	allocator, _ := newAllocator(t)

	cases := []struct {
		name string
		req  Request
	}{
		{"egasi yo'q", Request{Kind: KindNode, Parent: netip.MustParsePrefix(tenantNet), PrefixLen: 128}},
		{"ota-prefiks yaroqsiz", Request{Kind: KindNode, Owner: "n", PrefixLen: 128}},
		{"uzunlik teskari", Request{
			Kind: KindNode, Owner: "n",
			Parent:    netip.MustParsePrefix(tenantNet),
			PrefixLen: 48,
		}},
		{"IPv4", Request{
			Kind: KindNode, Owner: "n",
			Parent:    netip.MustParsePrefix("10.0.0.0/8"),
			PrefixLen: 32,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := allocator.Allocate(t.Context(), tc.req); err == nil {
				t.Error("xato kutilgan edi")
			}
		})
	}
}

// Pool tugaganda aniq xato qaytishi kerak.
func TestAllocate_PoolExhaustion(t *testing.T) {
	allocator, _ := newAllocator(t)

	// /126 ichida atigi 4 ta /128 bor.
	parent := netip.MustParsePrefix("2a0e:1234:1::/126")

	for i := range 4 {
		if _, err := allocator.Allocate(t.Context(), Request{
			Kind:      KindNode,
			Owner:     fmt.Sprintf("node-%d", i),
			Parent:    parent,
			PrefixLen: 128,
		}); err != nil {
			t.Fatalf("Allocate %d: %v", i, err)
		}
	}

	_, err := allocator.Allocate(t.Context(), Request{
		Kind:      KindNode,
		Owner:     "node-toshib-ketdi",
		Parent:    parent,
		PrefixLen: 128,
	})
	if !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("ErrPoolExhausted kutilgan, olindi: %v", err)
	}
}

// Store xatoda avtomatik orqaga qaytarmaydi (ataylab, O(N) nusxalashdan
// qochish uchun) — shuning uchun Allocator o'zi tekshiruvni yozishdan
// oldin bajarishi SHART. Bu test aynan shuni qo'riqlaydi.
func TestAllocate_FailureLeavesStateIntact(t *testing.T) {
	allocator, _ := newAllocator(t)

	// /126 da atigi 4 ta manzil bor — to'ldiramiz.
	parent := netip.MustParsePrefix("2a0e:1234:1::/126")
	filled := make(map[netip.Prefix]bool, 4)

	for i := range 4 {
		lease, err := allocator.Allocate(t.Context(), Request{
			Kind: KindNode, Owner: fmt.Sprintf("node-%d", i),
			Parent: parent, PrefixLen: 128,
		})
		if err != nil {
			t.Fatalf("Allocate %d: %v", i, err)
		}
		filled[lease.Prefix] = true
	}

	// Endi taqsimlash muvaffaqiyatsiz bo'ladi.
	if _, err := allocator.Allocate(t.Context(), Request{
		Kind: KindNode, Owner: "node-ortiqcha",
		Parent: parent, PrefixLen: 128,
	}); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("ErrPoolExhausted kutilgan, olindi: %v", err)
	}

	// Mavjud ijaralar buzilmagan bo'lishi kerak.
	leases, err := allocator.Leases(t.Context())
	if err != nil {
		t.Fatalf("Leases: %v", err)
	}
	if len(leases) != 4 {
		t.Fatalf("4 ta ijara kutilgan, %d olindi", len(leases))
	}
	for _, lease := range leases {
		if !filled[lease.Prefix] {
			t.Errorf("kutilmagan prefiks: %v", lease.Prefix)
		}
	}
}

// Sticky tiklash muvaffaqiyatsiz tugasa, karantindagi yozuv joyida
// qolishi kerak — aks holda u jimgina yo'qolardi.
func TestAllocate_FailedStickyRestoresQuarantine(t *testing.T) {
	allocator, _ := newAllocator(t)

	// /127 da 2 ta manzil.
	parent := netip.MustParsePrefix("2a0e:1234:1::/127")

	first, err := allocator.Allocate(t.Context(), Request{
		Kind: KindNode, Owner: "node-1", Parent: parent, PrefixLen: 128,
	})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if _, err := allocator.Allocate(t.Context(), Request{
		Kind: KindNode, Owner: "node-2", Parent: parent, PrefixLen: 128,
	}); err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	if err := allocator.Release(t.Context(), first.ID); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// node-1 o'z manzilini qaytarib olishi kerak (sticky).
	again, err := allocator.Allocate(t.Context(), Request{
		Kind: KindNode, Owner: "node-1", Parent: parent,
		PrefixLen: 128, Preferred: first.Prefix,
	})
	if err != nil {
		t.Fatalf("sticky Allocate: %v", err)
	}
	if again.Prefix != first.Prefix {
		t.Errorf("%v kutilgan, %v olindi", first.Prefix, again.Prefix)
	}
}

func BenchmarkAllocate_Node(b *testing.B) {
	c := newClock()
	allocator, _ := New(Options{Store: NewMemoryStore(), Now: c.Now})

	ctx := context.Background()
	for i := 0; b.Loop(); i++ {
		if _, err := allocator.Allocate(ctx, nodeRequest(fmt.Sprintf("node-%d", i))); err != nil {
			b.Fatal(err)
		}
	}
}
