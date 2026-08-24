package registry

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

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

func newRegistry(t *testing.T) (*Registry, *clock) {
	t.Helper()
	c := newClock()
	return New(Options{Now: c.Now}), c
}

func key(seed string) PublicKey {
	var k PublicKey
	copy(k[:], seed)
	return k
}

func register(t *testing.T, r *Registry, tenant, name string, addr string) *Node {
	t.Helper()

	node, err := r.Register(Registration{
		PublicKey: key(name),
		Tenant:    tenant,
		Hostname:  name,
		Addresses: []netip.Prefix{netip.MustParsePrefix(addr)},
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:51820")},
	})
	if err != nil {
		t.Fatalf("Register(%s): %v", name, err)
	}
	return node
}

// ═══════════════ Ro'yxatga olish ═══════════════

func TestRegister_DerivesIDFromPublicKey(t *testing.T) {
	r, _ := newRegistry(t)

	node := register(t, r, "t1", "laptop", "2a0e:1234:1::1/128")

	if node.ID != NodeID(key("laptop")) {
		t.Errorf("ID kalitdan hosil qilinishi kerak, olindi %q", node.ID)
	}
	if len(node.ID) != 64 {
		t.Errorf("SHA-256 hex 64 belgi bo'lishi kerak, %d olindi", len(node.ID))
	}
}

// Bir xil kalit bilan qayta ro'yxatdan o'tish yangi node yaratmasligi
// kerak — klient qayta ulanishi odatiy hol.
func TestRegister_IsIdempotent(t *testing.T) {
	r, _ := newRegistry(t)

	first := register(t, r, "t1", "laptop", "2a0e:1234:1::1/128")
	second := register(t, r, "t1", "laptop", "2a0e:1234:1::1/128")

	if first.ID != second.ID {
		t.Errorf("bir xil ID kutilgan: %s va %s", first.ID, second.ID)
	}
	if !first.CreatedAt.Equal(second.CreatedAt) {
		t.Error("CreatedAt o'zgarmasligi kerak")
	}
}

func TestRegister_Validation(t *testing.T) {
	r, _ := newRegistry(t)

	if _, err := r.Register(Registration{PublicKey: key("a")}); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("ErrTenantRequired kutilgan, olindi: %v", err)
	}
	if _, err := r.Register(Registration{Tenant: "t1"}); !errors.Is(err, ErrKeyRequired) {
		t.Errorf("ErrKeyRequired kutilgan, olindi: %v", err)
	}
}

func TestRegister_ReturnsCopy(t *testing.T) {
	r, _ := newRegistry(t)

	node := register(t, r, "t1", "laptop", "2a0e:1234:1::1/128")
	node.Addresses[0] = netip.MustParsePrefix("::/0")

	stored, _ := r.Node(node.ID)
	if stored.Addresses[0].Bits() == 0 {
		t.Fatal("Register nusxa emas — tashqaridan o'zgartirib bo'ldi")
	}
}

// ═══════════════ Tenant izolyatsiyasi ═══════════════

func TestNetworkMap_OnlyShowsOwnTenant(t *testing.T) {
	r, _ := newRegistry(t)

	alice := register(t, r, "t1", "alice", "2a0e:1234:1::1/128")
	register(t, r, "t1", "bob", "2a0e:1234:1::2/128")
	register(t, r, "t2", "stranger", "2a0e:9999:1::1/128")

	netmap, err := r.NetworkMapFor(alice.ID, 0)
	if err != nil {
		t.Fatalf("NetworkMapFor: %v", err)
	}

	if len(netmap.Peers) != 1 {
		t.Fatalf("1 peer kutilgan, %d olindi", len(netmap.Peers))
	}
	if netmap.Peers[0].Hostname != "bob" {
		t.Errorf("bob kutilgan, %q olindi", netmap.Peers[0].Hostname)
	}
}

// Node o'zi bilan sessiya qurmaydi — u peerlar ro'yxatida bo'lmasligi
// kerak.
func TestNetworkMap_SelfIsNotAPeer(t *testing.T) {
	r, _ := newRegistry(t)

	alice := register(t, r, "t1", "alice", "2a0e:1234:1::1/128")
	register(t, r, "t1", "bob", "2a0e:1234:1::2/128")

	netmap, _ := r.NetworkMapFor(alice.ID, 0)

	if netmap.Self == nil || netmap.Self.ID != alice.ID {
		t.Fatal("Self to'ldirilmagan")
	}
	for _, peer := range netmap.Peers {
		if peer.ID == alice.ID {
			t.Error("node o'zi peerlar ro'yxatida")
		}
	}
}

func TestNetworkMap_UnknownNode(t *testing.T) {
	r, _ := newRegistry(t)

	if _, err := r.NetworkMapFor("yoq", 0); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("ErrNodeNotFound kutilgan, olindi: %v", err)
	}
}

// ═══════════════ Delta sync ═══════════════

func TestNetworkMap_FirstRequestIsFull(t *testing.T) {
	r, _ := newRegistry(t)

	alice := register(t, r, "t1", "alice", "2a0e:1234:1::1/128")
	register(t, r, "t1", "bob", "2a0e:1234:1::2/128")

	netmap, _ := r.NetworkMapFor(alice.ID, 0)

	if !netmap.Full {
		t.Error("birinchi so'rov to'liq map bo'lishi kerak")
	}
	if len(netmap.Peers) != 1 {
		t.Errorf("1 peer kutilgan, %d olindi", len(netmap.Peers))
	}
}

func TestNetworkMap_NoChangesGivesEmptyDelta(t *testing.T) {
	r, _ := newRegistry(t)

	alice := register(t, r, "t1", "alice", "2a0e:1234:1::1/128")
	register(t, r, "t1", "bob", "2a0e:1234:1::2/128")

	first, _ := r.NetworkMapFor(alice.ID, 0)
	second, _ := r.NetworkMapFor(alice.ID, first.Version)

	if !second.Empty() {
		t.Errorf("bo'sh delta kutilgan: %d peer, %d o'chirilgan",
			len(second.Peers), len(second.Removed))
	}
	if second.Version != first.Version {
		t.Errorf("versiya o'zgarmasligi kerak: %d → %d", first.Version, second.Version)
	}
}

func TestNetworkMap_DeltaCarriesOnlyChanges(t *testing.T) {
	r, _ := newRegistry(t)

	alice := register(t, r, "t1", "alice", "2a0e:1234:1::1/128")
	register(t, r, "t1", "bob", "2a0e:1234:1::2/128")

	base, _ := r.NetworkMapFor(alice.ID, 0)

	// Uchinchi node qo'shiladi.
	register(t, r, "t1", "carol", "2a0e:1234:1::3/128")

	delta, _ := r.NetworkMapFor(alice.ID, base.Version)

	if delta.Full {
		t.Error("delta kutilgan, to'liq map olindi")
	}
	if len(delta.Peers) != 1 {
		t.Fatalf("1 o'zgargan peer kutilgan, %d olindi", len(delta.Peers))
	}
	if delta.Peers[0].Hostname != "carol" {
		t.Errorf("carol kutilgan, %q olindi", delta.Peers[0].Hostname)
	}
	if len(delta.Removed) != 0 {
		t.Errorf("o'chirilganlar bo'lmasligi kerak: %v", delta.Removed)
	}
}

func TestNetworkMap_DeltaReportsRemovals(t *testing.T) {
	r, _ := newRegistry(t)

	alice := register(t, r, "t1", "alice", "2a0e:1234:1::1/128")
	bob := register(t, r, "t1", "bob", "2a0e:1234:1::2/128")

	base, _ := r.NetworkMapFor(alice.ID, 0)

	if err := r.Unregister(bob.ID); err != nil {
		t.Fatalf("Unregister: %v", err)
	}

	delta, _ := r.NetworkMapFor(alice.ID, base.Version)

	if len(delta.Removed) != 1 || delta.Removed[0] != bob.ID {
		t.Errorf("bob o'chirilgan deb ko'rsatilishi kerak: %v", delta.Removed)
	}
	if len(delta.Peers) != 0 {
		t.Errorf("o'zgargan peer bo'lmasligi kerak: %d", len(delta.Peers))
	}
}

// Bitta node bir necha marta o'zgarsa, deltada FAQAT BIR MARTA
// bo'lishi kerak — klientga oraliq holatlar kerak emas.
func TestNetworkMap_DeltaCollapsesRepeatedChanges(t *testing.T) {
	r, _ := newRegistry(t)

	alice := register(t, r, "t1", "alice", "2a0e:1234:1::1/128")
	bob := register(t, r, "t1", "bob", "2a0e:1234:1::2/128")

	base, _ := r.NetworkMapFor(alice.ID, 0)

	for i := range 5 {
		if err := r.Heartbeat(bob.ID, []netip.AddrPort{
			netip.MustParseAddrPort(fmt.Sprintf("203.0.113.%d:51820", i+10)),
		}); err != nil {
			t.Fatalf("Heartbeat: %v", err)
		}
	}

	delta, _ := r.NetworkMapFor(alice.ID, base.Version)

	if len(delta.Peers) != 1 {
		t.Fatalf("1 peer kutilgan, %d olindi", len(delta.Peers))
	}
	// Eng oxirgi endpoint bo'lishi kerak.
	if got := delta.Peers[0].Endpoints[0].Port(); got != 51820 {
		t.Errorf("port: %d", got)
	}
	if got := delta.Peers[0].Endpoints[0].Addr().String(); got != "203.0.113.14" {
		t.Errorf("eng oxirgi endpoint kutilgan, %q olindi", got)
	}
}

// Node o'chirilib, keyin qayta qo'shilsa — delta uni MAVJUD deb
// ko'rsatishi kerak, o'chirilgan emas.
func TestNetworkMap_RemovedThenReaddedAppearsAsPeer(t *testing.T) {
	r, _ := newRegistry(t)

	alice := register(t, r, "t1", "alice", "2a0e:1234:1::1/128")
	bob := register(t, r, "t1", "bob", "2a0e:1234:1::2/128")

	base, _ := r.NetworkMapFor(alice.ID, 0)

	if err := r.Unregister(bob.ID); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	register(t, r, "t1", "bob", "2a0e:1234:1::2/128")

	delta, _ := r.NetworkMapFor(alice.ID, base.Version)

	if len(delta.Removed) != 0 {
		t.Errorf("o'chirilgan deb ko'rsatilmasligi kerak: %v", delta.Removed)
	}
	if len(delta.Peers) != 1 || delta.Peers[0].ID != bob.ID {
		t.Errorf("bob peer sifatida kutilgan: %+v", delta.Peers)
	}
}

// Jurnal to'lganda juda orqada qolgan klient to'liq map olishi kerak —
// aks holda u o'zgarishlarni jimgina o'tkazib yuborardi.
func TestNetworkMap_FallsBackToFullWhenLogTruncated(t *testing.T) {
	c := newClock()
	r := New(Options{Now: c.Now, LogLimit: 4})

	alice, err := r.Register(Registration{
		PublicKey: key("alice"), Tenant: "t1",
		Addresses: []netip.Prefix{netip.MustParsePrefix("2a0e:1234:1::1/128")},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	base, _ := r.NetworkMapFor(alice.ID, 0)

	// Jurnalni to'ldirib yuboramiz.
	for i := range 10 {
		register(t, r, "t1", fmt.Sprintf("node-%d", i), "2a0e:1234:1::9/128")
	}

	netmap, _ := r.NetworkMapFor(alice.ID, base.Version)

	if !netmap.Full {
		t.Error("jurnal kesilgach to'liq map kutilgan edi")
	}
	if len(netmap.Peers) != 10 {
		t.Errorf("10 peer kutilgan, %d olindi", len(netmap.Peers))
	}
}

// ═══════════════ Heartbeat va muddat ═══════════════

// Har 30 sekundlik heartbeat butun tenantga delta yuborishga sabab
// bo'lmasligi kerak.
func TestHeartbeat_WithoutChangesDoesNotBumpVersion(t *testing.T) {
	r, _ := newRegistry(t)

	node := register(t, r, "t1", "laptop", "2a0e:1234:1::1/128")
	before := r.Version()

	for range 5 {
		if err := r.Heartbeat(node.ID, node.Endpoints); err != nil {
			t.Fatalf("Heartbeat: %v", err)
		}
	}

	if after := r.Version(); after != before {
		t.Errorf("versiya oshmasligi kerak: %d → %d", before, after)
	}
}

func TestHeartbeat_EndpointChangeBumpsVersion(t *testing.T) {
	r, _ := newRegistry(t)

	node := register(t, r, "t1", "laptop", "2a0e:1234:1::1/128")
	before := r.Version()

	if err := r.Heartbeat(node.ID, []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.7:51820"),
	}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	if after := r.Version(); after <= before {
		t.Errorf("versiya oshishi kerak: %d → %d", before, after)
	}
}

func TestHeartbeat_UnknownNode(t *testing.T) {
	r, _ := newRegistry(t)

	if err := r.Heartbeat("yoq", nil); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("ErrNodeNotFound kutilgan, olindi: %v", err)
	}
}

func TestExpire_RemovesStaleNodes(t *testing.T) {
	r, c := newRegistry(t)

	alice := register(t, r, "t1", "alice", "2a0e:1234:1::1/128")
	bob := register(t, r, "t1", "bob", "2a0e:1234:1::2/128")

	c.advance(DefaultTTL / 2)
	if err := r.Heartbeat(alice.ID, nil); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	c.advance(DefaultTTL/2 + time.Second)

	if removed := r.Expire(); removed != 1 {
		t.Errorf("1 ta o'chirilishi kerak edi, %d olindi", removed)
	}

	if _, ok := r.Node(bob.ID); ok {
		t.Error("bob o'chirilmadi")
	}
	if _, ok := r.Node(alice.ID); !ok {
		t.Error("alice o'chirilib ketdi")
	}
}

// ═══════════════ Watch ═══════════════

func TestWatch_NotifiesOnChange(t *testing.T) {
	r, _ := newRegistry(t)

	register(t, r, "t1", "alice", "2a0e:1234:1::1/128")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	updates := r.Watch(ctx, "t1")

	register(t, r, "t1", "bob", "2a0e:1234:1::2/128")

	select {
	case version := <-updates:
		if version == 0 {
			t.Error("versiya 0 bo'lmasligi kerak")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("xabar kelmadi")
	}
}

func TestWatch_IgnoresOtherTenants(t *testing.T) {
	r, _ := newRegistry(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	updates := r.Watch(ctx, "t1")

	register(t, r, "t2", "stranger", "2a0e:9999:1::1/128")

	select {
	case version := <-updates:
		t.Fatalf("begona tenant o'zgarishi haqida xabar keldi: %d", version)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestWatch_UnregistersOnContextCancel(t *testing.T) {
	r, _ := newRegistry(t)

	ctx, cancel := context.WithCancel(t.Context())
	updates := r.Watch(ctx, "t1")

	if r.Watchers() != 1 {
		t.Fatalf("1 kuzatuvchi kutilgan, %d olindi", r.Watchers())
	}

	cancel()

	// Kanal yopilishini kutamiz.
	select {
	case _, open := <-updates:
		if open {
			// Bekor qilishdan oldin kelgan xabar bo'lishi mumkin;
			// keyingisi yopilgan bo'lishi kerak.
			if _, stillOpen := <-updates; stillOpen {
				t.Error("kanal yopilmadi")
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("kanal yopilmadi")
	}

	if r.Watchers() != 0 {
		t.Errorf("kuzatuvchi tozalanmadi: %d", r.Watchers())
	}
}

// Sekin kuzatuvchi registryni bloklab qo'ymasligi kerak.
func TestWatch_SlowWatcherDoesNotBlockRegistry(t *testing.T) {
	r, _ := newRegistry(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	_ = r.Watch(ctx, "t1") // ataylab o'qimaymiz

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 100 {
			register(t, r, "t1", fmt.Sprintf("node-%d", i), "2a0e:1234:1::9/128")
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("registry sekin kuzatuvchi sababli bloklandi")
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r, _ := newRegistry(t)

	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 50 {
				node, err := r.Register(Registration{
					PublicKey: key(fmt.Sprintf("w%d-n%d", worker, i)),
					Tenant:    "t1",
					Addresses: []netip.Prefix{netip.MustParsePrefix("2a0e:1234:1::1/128")},
				})
				if err != nil {
					t.Errorf("Register: %v", err)
					return
				}
				if _, err := r.NetworkMapFor(node.ID, 0); err != nil {
					t.Errorf("NetworkMapFor: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkNetworkMap_Delta(b *testing.B) {
	c := newClock()
	r := New(Options{Now: c.Now})

	var selfID string
	for i := range 500 {
		node, _ := r.Register(Registration{
			PublicKey: key(fmt.Sprintf("node-%d", i)),
			Tenant:    "t1",
			Addresses: []netip.Prefix{netip.MustParsePrefix("2a0e:1234:1::1/128")},
		})
		if i == 0 {
			selfID = node.ID
		}
	}

	version := r.Version()
	for b.Loop() {
		if _, err := r.NetworkMapFor(selfID, version); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNetworkMap_Full(b *testing.B) {
	c := newClock()
	r := New(Options{Now: c.Now})

	var selfID string
	for i := range 500 {
		node, _ := r.Register(Registration{
			PublicKey: key(fmt.Sprintf("node-%d", i)),
			Tenant:    "t1",
			Addresses: []netip.Prefix{netip.MustParsePrefix("2a0e:1234:1::1/128")},
		})
		if i == 0 {
			selfID = node.ID
		}
	}

	for b.Loop() {
		if _, err := r.NetworkMapFor(selfID, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// TagIndex tag → manzillar xaritasini berishi kerak: policy
// kompilyatori aynan shunga tayanadi.
func TestTagIndex_GroupsByTag(t *testing.T) {
	reg := New(Options{})

	for i, spec := range []struct {
		host string
		tags []string
	}{
		{"web-1", []string{"tag:web", "tag:prod"}},
		{"web-2", []string{"tag:web"}},
		{"db-1", []string{"tag:db"}},
	} {
		var key PublicKey
		key[0] = byte(i + 1)

		if _, err := reg.Register(Registration{
			PublicKey: key,
			Tenant:    "t1",
			Hostname:  spec.host,
			Tags:      spec.tags,
			Addresses: []netipPrefix{netip.MustParsePrefix(
				"2a0e:1::" + string(rune('1'+i)) + "/128")},
		}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	index := reg.TagIndex("t1")

	if got := len(index["tag:web"]); got != 2 {
		t.Errorf("tag:web da %d ta manzil, 2 kutilgan edi", got)
	}
	if got := len(index["tag:db"]); got != 1 {
		t.Errorf("tag:db da %d ta manzil, 1 kutilgan edi", got)
	}
	if got := len(index["tag:prod"]); got != 1 {
		t.Errorf("tag:prod da %d ta manzil, 1 kutilgan edi", got)
	}
}

// Tenant izolyatsiyasi tag'larga ham tegishli bo'lishi kerak.
func TestTagIndex_IsolatesTenants(t *testing.T) {
	reg := New(Options{})

	for i, tenant := range []string{"t1", "t2"} {
		var key PublicKey
		key[0] = byte(i + 1)

		if _, err := reg.Register(Registration{
			PublicKey: key,
			Tenant:    tenant,
			Tags:      []string{"tag:web"},
			Addresses: []netipPrefix{netip.MustParsePrefix(
				"2a0e:1::" + string(rune('1'+i)) + "/128")},
		}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	if got := len(reg.TagIndex("t1")["tag:web"]); got != 1 {
		t.Errorf("t1 da %d ta manzil ko'rindi, 1 kutilgan edi", got)
	}
}

// Tartib barqaror bo'lishi kerak: kompilyatsiya deterministik
// bo'lmasa, bir xil holat har safar boshqa versiya berardi va
// nodelar qoidalarni behuda qayta qo'llardi.
func TestTagIndex_StableOrder(t *testing.T) {
	reg := New(Options{})

	for i := range 5 {
		var key PublicKey
		key[0] = byte(i + 1)

		if _, err := reg.Register(Registration{
			PublicKey: key,
			Tenant:    "t1",
			Tags:      []string{"tag:web"},
			Addresses: []netipPrefix{netip.MustParsePrefix(
				"2a0e:1::" + string(rune('1'+i)) + "/128")},
		}); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	first := reg.TagIndex("t1")["tag:web"]
	for range 5 {
		next := reg.TagIndex("t1")["tag:web"]
		for i := range first {
			if first[i] != next[i] {
				t.Fatalf("tartib o'zgardi: %v va %v", first, next)
			}
		}
	}
}
