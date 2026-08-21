package router

import (
	"net/netip"
	"testing"

	"github.com/freco-dev/cc01/daemon/noise"
)

func testPeer(t *testing.T, name string) *Peer {
	t.Helper()

	var key noise.PublicKey
	copy(key[:], name)
	return &Peer{PublicKey: key}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("prefiks %q: %v", s, err)
	}
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("manzil %q: %v", s, err)
	}
	return a
}

func TestTrie_ExactMatch(t *testing.T) {
	tr := newTrie()
	alice := testPeer(t, "alice")

	tr.insert(mustPrefix(t, "2a0e:1234:1::b7f2/128"), alice)

	if got := tr.lookup(mustAddr(t, "2a0e:1234:1::b7f2")); got != alice {
		t.Errorf("aniq moslik topilmadi: %v", got)
	}
	if got := tr.lookup(mustAddr(t, "2a0e:1234:1::b7f3")); got != nil {
		t.Errorf("qo'shni manzil mos kelmasligi kerak: %v", got)
	}
}

// Eng uzun moslik g'olib: exit-node (::/0) va tenant (/64) bir vaqtda
// bo'lishi mumkin, aniqrog'i tanlanishi kerak.
func TestTrie_LongestPrefixWins(t *testing.T) {
	tr := newTrie()
	exitNode := testPeer(t, "exit")
	tenant := testPeer(t, "tenant")
	node := testPeer(t, "node")

	tr.insert(mustPrefix(t, "::/0"), exitNode)
	tr.insert(mustPrefix(t, "2a0e:1234:1::/64"), tenant)
	tr.insert(mustPrefix(t, "2a0e:1234:1::b7f2/128"), node)

	cases := []struct {
		addr string
		want *Peer
		why  string
	}{
		{"2a0e:1234:1::b7f2", node, "/128 eng aniq"},
		{"2a0e:1234:1::9999", tenant, "/64 ga tushadi"},
		{"2a0e:9999::1", exitNode, "faqat ::/0 mos keladi"},
		{"2001:db8::1", exitNode, "begona manzil ham exit-node'ga"},
	}

	for _, tc := range cases {
		if got := tr.lookup(mustAddr(t, tc.addr)); got != tc.want {
			t.Errorf("%s (%s): %v kutilgan, %v olindi", tc.addr, tc.why, tc.want, got)
		}
	}
}

func TestTrie_NoMatchReturnsNil(t *testing.T) {
	tr := newTrie()
	tr.insert(mustPrefix(t, "2a0e:1234:1::/64"), testPeer(t, "alice"))

	if got := tr.lookup(mustAddr(t, "fd00::1")); got != nil {
		t.Errorf("mos kelmasligi kerak edi: %v", got)
	}
}

func TestTrie_DefaultRouteAlone(t *testing.T) {
	tr := newTrie()
	exitNode := testPeer(t, "exit")

	tr.insert(mustPrefix(t, "::/0"), exitNode)

	for _, addr := range []string{"2a0e::1", "fd00::1", "::1", "ff02::1"} {
		if got := tr.lookup(mustAddr(t, addr)); got != exitNode {
			t.Errorf("%s: ::/0 ga tushishi kerak, %v olindi", addr, got)
		}
	}
}

func TestTrie_ReinsertReplacesOwner(t *testing.T) {
	tr := newTrie()
	alice := testPeer(t, "alice")
	bob := testPeer(t, "bob")

	prefix := mustPrefix(t, "2a0e:1234:1::/64")
	tr.insert(prefix, alice)
	tr.insert(prefix, bob)

	if got := tr.lookup(mustAddr(t, "2a0e:1234:1::5")); got != bob {
		t.Errorf("yangi egasi kutilgan, %v olindi", got)
	}
}

func TestTrie_RemovePeerClearsAllPrefixes(t *testing.T) {
	tr := newTrie()
	alice := testPeer(t, "alice")
	bob := testPeer(t, "bob")

	tr.insert(mustPrefix(t, "2a0e:1234:1::/64"), alice)
	tr.insert(mustPrefix(t, "2a0e:1234:2::/64"), alice)
	tr.insert(mustPrefix(t, "2a0e:1234:3::/64"), bob)

	tr.removePeer(alice)

	if got := tr.lookup(mustAddr(t, "2a0e:1234:1::5")); got != nil {
		t.Errorf("alice birinchi prefiksi qoldi: %v", got)
	}
	if got := tr.lookup(mustAddr(t, "2a0e:1234:2::5")); got != nil {
		t.Errorf("alice ikkinchi prefiksi qoldi: %v", got)
	}

	// Bob tegilmasligi kerak.
	if got := tr.lookup(mustAddr(t, "2a0e:1234:3::5")); got != bob {
		t.Errorf("bob prefiksi yo'qoldi: %v", got)
	}
}

// Prefiks chegaralari — daraxtda eng xato chiqadigan joy.
func TestTrie_PrefixBoundaries(t *testing.T) {
	tr := newTrie()
	peer := testPeer(t, "p")

	tr.insert(mustPrefix(t, "2a0e:1234:1::/48"), peer)

	inside := []string{
		"2a0e:1234:1::1",
		"2a0e:1234:1:ffff:ffff:ffff:ffff:ffff",
		"2a0e:1234:1::",
	}
	for _, addr := range inside {
		if got := tr.lookup(mustAddr(t, addr)); got != peer {
			t.Errorf("%s ichida bo'lishi kerak", addr)
		}
	}

	outside := []string{
		"2a0e:1234:0:ffff::1", // bitta blok oldin
		"2a0e:1234:2::1",      // bitta blok keyin
	}
	for _, addr := range outside {
		if got := tr.lookup(mustAddr(t, addr)); got != nil {
			t.Errorf("%s tashqarida bo'lishi kerak, %v olindi", addr, got)
		}
	}
}

func TestTrie_IPv4IsIgnored(t *testing.T) {
	tr := newTrie()
	tr.insert(mustPrefix(t, "::/0"), testPeer(t, "exit"))

	// Overlay faqat IPv6 — IPv4 manzil qidiruvga tushmasligi kerak.
	if got := tr.lookup(mustAddr(t, "10.0.0.1")); got != nil {
		t.Errorf("IPv4 e'tiborsiz qoldirilishi kerak, %v olindi", got)
	}
}

func BenchmarkTrie_Lookup(b *testing.B) {
	tr := newTrie()

	// 500 peer — ARCHITECTURE.md §8 dagi full-mesh chegarasi.
	for i := range 500 {
		var key noise.PublicKey
		key[0], key[1] = byte(i>>8), byte(i)

		prefix := netip.PrefixFrom(
			netip.AddrFrom16([16]byte{0x2a, 0x0e, 0x12, 0x34, byte(i >> 8), byte(i)}), 64)
		tr.insert(prefix, &Peer{PublicKey: key})
	}

	target := netip.AddrFrom16([16]byte{0x2a, 0x0e, 0x12, 0x34, 0x01, 0x2c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	for b.Loop() {
		tr.lookup(target)
	}
}
