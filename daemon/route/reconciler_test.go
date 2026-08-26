package route

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/router"
	"github.com/freco-dev/cc01/daemon/tun"
)

// fakeSink yadro o'rniga: qo'yilgan marshrutlarni eslab qoladi.
type fakeSink struct {
	mu      sync.Mutex
	current []netip.Prefix
	calls   int
	err     error
}

func (s *fakeSink) SetRoutes(desired []netip.Prefix) (tun.RouteDiff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls++
	if s.err != nil {
		return tun.RouteDiff{}, s.err
	}

	var diff tun.RouteDiff
	for _, prefix := range desired {
		if !slices.Contains(s.current, prefix) {
			diff.Added = append(diff.Added, prefix)
		}
	}
	for _, prefix := range s.current {
		if !slices.Contains(desired, prefix) {
			diff.Removed = append(diff.Removed, prefix)
		}
	}

	s.current = slices.Clone(desired)
	return diff, nil
}

func (s *fakeSink) routes() []netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()

	return slices.Clone(s.current)
}

func (s *fakeSink) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.calls
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newRouterWith berilgan allowed_ips li peerlardan router yasaydi.
func newRouterWith(t *testing.T, allowed ...[]netip.Prefix) *router.Router {
	t.Helper()

	r := router.New()
	for _, prefixes := range allowed {
		peer, err := noise.GenerateIdentity()
		if err != nil {
			t.Fatalf("peer identity: %v", err)
		}
		if _, err := r.AddPeer(peer.PublicKey(), prefixes); err != nil {
			t.Fatalf("AddPeer: %v", err)
		}
	}
	return r
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()

	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("prefiks %q: %v", s, err)
	}
	return prefix
}

// Tenant /64 ichidagi peer /128 lari uchun alohida marshrut kerak emas.
func TestDesired_SkipsPrefixesCoveredByBase(t *testing.T) {
	base := mustPrefix(t, "fd00:cc01:beef::/64")
	inside := mustPrefix(t, "fd00:cc01:beef::5/128")

	r := New(Config{
		Base:   []netip.Prefix{base},
		Peers:  newRouterWith(t, []netip.Prefix{inside}),
		Sink:   &fakeSink{},
		Logger: quietLogger(),
	})

	desired := r.desired()
	if len(desired) != 1 || desired[0] != base {
		t.Fatalf("faqat base kutilgan edi, olindi: %v", desired)
	}
}

// Subnet router tenant prefiksidan tashqarida — marshrut kerak.
func TestDesired_KeepsPrefixesOutsideBase(t *testing.T) {
	base := mustPrefix(t, "fd00:cc01:beef::/64")
	subnet := mustPrefix(t, "2a0e:1234:5678::/48")

	r := New(Config{
		Base:   []netip.Prefix{base},
		Peers:  newRouterWith(t, []netip.Prefix{subnet}),
		Sink:   &fakeSink{},
		Logger: quietLogger(),
	})

	desired := r.desired()
	if !slices.Contains(desired, subnet) {
		t.Fatalf("subnet marshruti yo'qolgan: %v", desired)
	}
}

// Peer ketganda uning marshruti ham ketishi kerak — DoD: 0 orphan.
func TestOnce_RemovesRouteWhenPeerLeaves(t *testing.T) {
	base := mustPrefix(t, "fd00:cc01:beef::/64")
	subnet := mustPrefix(t, "2a0e:1234:5678::/48")

	peers := newRouterWith(t, []netip.Prefix{subnet})
	sink := &fakeSink{}

	r := New(Config{
		Base: []netip.Prefix{base}, Peers: peers, Sink: sink, Logger: quietLogger(),
	})

	if _, err := r.Once(); err != nil {
		t.Fatalf("birinchi Once: %v", err)
	}
	if !slices.Contains(sink.routes(), subnet) {
		t.Fatalf("subnet qo'yilmagan: %v", sink.routes())
	}

	for _, peer := range peers.Peers() {
		peers.RemovePeer(peer.PublicKey)
	}

	diff, err := r.Once()
	if err != nil {
		t.Fatalf("ikkinchi Once: %v", err)
	}
	if !slices.Contains(diff.Removed, subnet) {
		t.Errorf("diff o'chirishni ko'rsatmadi: %s", diff)
	}
	if slices.Contains(sink.routes(), subnet) {
		t.Errorf("orphan marshrut qoldi: %v", sink.routes())
	}
}

// Holat o'zgarmasa yadroga tegilmasligi kerak.
func TestOnce_NoChangeProducesEmptyDiff(t *testing.T) {
	base := mustPrefix(t, "fd00:cc01:beef::/64")
	sink := &fakeSink{}

	r := New(Config{
		Base: []netip.Prefix{base}, Peers: newRouterWith(t), Sink: sink, Logger: quietLogger(),
	})

	if _, err := r.Once(); err != nil {
		t.Fatalf("Once: %v", err)
	}

	diff, err := r.Once()
	if err != nil {
		t.Fatalf("Once: %v", err)
	}
	if !diff.Empty() {
		t.Errorf("o'zgarish kutilmagan edi: %s", diff)
	}
}

// Xato bo'lsa Synced() yolg'on gapirmasligi kerak.
func TestOnce_FailureClearsSynced(t *testing.T) {
	sink := &fakeSink{err: errors.New("netlink tushdi")}

	r := New(Config{
		Base:   []netip.Prefix{mustPrefix(t, "fd00:cc01:beef::/64")},
		Peers:  newRouterWith(t),
		Sink:   sink,
		Logger: quietLogger(),
	})

	if _, err := r.Once(); err == nil {
		t.Fatal("xato kutilgan edi")
	}
	if r.Synced() {
		t.Error("Synced() xatodan keyin ham true")
	}
}

// Poke bloklanmasligi kerak: uni NetworkMap yo'li chaqiradi.
func TestPoke_NeverBlocks(t *testing.T) {
	r := New(Config{
		Base: nil, Peers: newRouterWith(t), Sink: &fakeSink{}, Logger: quietLogger(),
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			r.Poke()
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Poke bloklandi")
	}
}

// Run darhol bir marta ishlashi kerak, birinchi tikni kutmasdan.
func TestRun_ReconcilesImmediately(t *testing.T) {
	sink := &fakeSink{}

	r := New(Config{
		Base:     []netip.Prefix{mustPrefix(t, "fd00:cc01:beef::/64")},
		Peers:    newRouterWith(t),
		Sink:     sink,
		Interval: time.Hour, // tik hech qachon kelmaydi
		Logger:   quietLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go r.Run(ctx)

	deadline := time.After(2 * time.Second)
	for sink.callCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("Run darhol moslashtirmadi")
		case <-time.After(5 * time.Millisecond):
		}
	}
}
