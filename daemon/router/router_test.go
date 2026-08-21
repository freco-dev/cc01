package router

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/freco-dev/cc01/daemon/noise"
)

// ipv6Packet minimal, lekin haqiqiy IPv6 paketi yasaydi.
func ipv6Packet(t *testing.T, src, dst string, payload ...byte) []byte {
	t.Helper()

	packet := make([]byte, ipv6HeaderLen+len(payload))
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = 59 // No Next Header
	packet[7] = 64 // Hop Limit

	copy(packet[srcOffset:], mustAddr(t, src).AsSlice())
	copy(packet[dstOffset:], mustAddr(t, dst).AsSlice())
	copy(packet[ipv6HeaderLen:], payload)

	return packet
}

func addPeer(t *testing.T, r *Router, name string, prefixes ...string) *Peer {
	t.Helper()

	var key noise.PublicKey
	copy(key[:], name)

	parsed := make([]netip.Prefix, len(prefixes))
	for i, p := range prefixes {
		parsed[i] = mustPrefix(t, p)
	}

	peer, err := r.AddPeer(key, parsed)
	if err != nil {
		t.Fatalf("AddPeer(%s): %v", name, err)
	}
	return peer
}

// ═══════════════ CRYPTOKEY ROUTING ═══════════════
//
// ARCHITECTURE.md §4.2 dagi "kritik nuqta". Bu testlar tarmoqning
// eng muhim xavfsizlik xususiyatini qo'riqlaydi.

func TestVerifyInbound_AcceptsOwnAddress(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", "2a0e:1234:1::/64")

	packet := ipv6Packet(t, "2a0e:1234:1::b7f2", "2a0e:1234:2::1")

	if err := r.VerifyInbound(alice, packet); err != nil {
		t.Fatalf("o'z manzilidan kelgan paket rad etildi: %v", err)
	}
}

// Asosiy hujum: qonuniy ulangan peer BOSHQA peerning manzilidan
// yozmoqchi. Bu 100% rad etilishi shart (§7.1 majburiy stsenariy 4).
func TestVerifyInbound_RejectsSpoofedPeerAddress(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", "2a0e:1234:1::/64")
	addPeer(t, r, "bob", "2a0e:1234:2::/64")

	// Alice o'zini Bob qilib ko'rsatmoqchi.
	spoofed := ipv6Packet(t, "2a0e:1234:2::1", "2a0e:1234:3::1")

	err := r.VerifyInbound(alice, spoofed)
	if !errors.Is(err, ErrSpoofedSource) {
		t.Fatalf("ErrSpoofedSource kutilgan edi, olindi: %v", err)
	}
}

func TestVerifyInbound_RejectsCompletelyForeignAddress(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", "2a0e:1234:1::/64")

	for _, src := range []string{
		"2001:db8::1",    // tashqi internet
		"fd00::1",        // begona ULA
		"::1",            // loopback
		"fe80::1",        // link-local
		"2a0e:1234:2::1", // qo'shni tenant
	} {
		packet := ipv6Packet(t, src, "2a0e:1234:1::b7f2")
		if err := r.VerifyInbound(alice, packet); !errors.Is(err, ErrSpoofedSource) {
			t.Errorf("%s rad etilishi kerak edi, olindi: %v", src, err)
		}
	}
}

// Chegara holatlari: prefiksning eng birinchi va eng oxirgi manzillari.
func TestVerifyInbound_PrefixBoundariesAreInclusive(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", "2a0e:1234:1::/64")

	for _, src := range []string{
		"2a0e:1234:1::",                     // birinchi
		"2a0e:1234:1:0:ffff:ffff:ffff:ffff", // oxirgi
	} {
		packet := ipv6Packet(t, src, "2a0e:1234:2::1")
		if err := r.VerifyInbound(alice, packet); err != nil {
			t.Errorf("%s qabul qilinishi kerak edi: %v", src, err)
		}
	}
}

func TestVerifyInbound_MultiplePrefixes(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", "2a0e:1234:1::/64", "fd01:cc01::/48")

	for _, src := range []string{"2a0e:1234:1::5", "fd01:cc01:0:1::9"} {
		packet := ipv6Packet(t, src, "2a0e:1234:9::1")
		if err := r.VerifyInbound(alice, packet); err != nil {
			t.Errorf("%s qabul qilinishi kerak edi: %v", src, err)
		}
	}

	packet := ipv6Packet(t, "fd02::1", "2a0e:1234:9::1")
	if err := r.VerifyInbound(alice, packet); !errors.Is(err, ErrSpoofedSource) {
		t.Errorf("fd02::1 rad etilishi kerak edi: %v", err)
	}
}

func TestVerifyInbound_RejectsMalformedPacket(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", "2a0e:1234:1::/64")

	if err := r.VerifyInbound(alice, make([]byte, 20)); !errors.Is(err, ErrShortPacket) {
		t.Errorf("qisqa paket: %v", err)
	}

	// IPv4 paket (versiya 4) — overlay faqat IPv6.
	ipv4 := make([]byte, ipv6HeaderLen)
	ipv4[0] = 4 << 4
	if err := r.VerifyInbound(alice, ipv4); !errors.Is(err, ErrNotIPv6) {
		t.Errorf("IPv4 paket: %v", err)
	}
}

// ═══════════════ Chiqish marshrutlashi ═══════════════

func TestRouteOutbound_FindsPeerByDestination(t *testing.T) {
	r := New()
	addPeer(t, r, "alice", "2a0e:1234:1::/64")
	bob := addPeer(t, r, "bob", "2a0e:1234:2::/64")

	packet := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:2::b7f2")

	peer, err := r.RouteOutbound(packet)
	// Sessiya yo'q — bu kutilgan, lekin peer topilishi kerak.
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("ErrNoSession kutilgan, olindi: %v", err)
	}
	if peer != bob {
		t.Errorf("bob kutilgan, %v olindi", peer)
	}
}

func TestRouteOutbound_UnknownDestination(t *testing.T) {
	r := New()
	addPeer(t, r, "alice", "2a0e:1234:1::/64")

	packet := ipv6Packet(t, "2a0e:1234:1::1", "2001:db8::1")

	if _, err := r.RouteOutbound(packet); !errors.Is(err, ErrNoRoute) {
		t.Fatalf("ErrNoRoute kutilgan, olindi: %v", err)
	}
}

func TestRouteOutbound_RequiresSession(t *testing.T) {
	r := New()
	bob := addPeer(t, r, "bob", "2a0e:1234:2::/64")

	packet := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:2::5")

	_, err := r.RouteOutbound(packet)
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("ErrNoSession kutilgan, olindi: %v", err)
	}

	// Sessiya bog'langach xato yo'qolishi kerak.
	session := establishSession(t)
	r.BindSession(bob, session)

	peer, err := r.RouteOutbound(packet)
	if err != nil {
		t.Fatalf("sessiya bog'langach xato: %v", err)
	}
	if peer != bob {
		t.Errorf("bob kutilgan, %v olindi", peer)
	}
}

// ═══════════════ Peer registri ═══════════════

func TestAddPeer_RejectsDuplicateKey(t *testing.T) {
	r := New()
	addPeer(t, r, "alice", "2a0e:1234:1::/64")

	var key noise.PublicKey
	copy(key[:], "alice")

	_, err := r.AddPeer(key, []netip.Prefix{mustPrefix(t, "2a0e:1234:9::/64")})
	if !errors.Is(err, ErrPeerExists) {
		t.Fatalf("ErrPeerExists kutilgan, olindi: %v", err)
	}
}

// Bir prefiks ikki peerga tegishli bo'lsa, ham marshrutlash, ham
// xavfsizlik tekshiruvi noaniq bo'lib qoladi.
func TestAddPeer_RejectsPrefixConflict(t *testing.T) {
	r := New()
	addPeer(t, r, "alice", "2a0e:1234:1::/64")

	var key noise.PublicKey
	copy(key[:], "bob")

	_, err := r.AddPeer(key, []netip.Prefix{mustPrefix(t, "2a0e:1234:1::/64")})
	if !errors.Is(err, ErrPrefixConflict) {
		t.Fatalf("ErrPrefixConflict kutilgan, olindi: %v", err)
	}

	// Konfliktdan keyin bob umuman qo'shilmagan bo'lishi kerak.
	if _, ok := r.Peer(key); ok {
		t.Error("konflikt bo'lsa ham peer qo'shilib qolgan")
	}
}

func TestAddPeer_RejectsIPv4Prefix(t *testing.T) {
	r := New()

	var key noise.PublicKey
	copy(key[:], "alice")

	_, err := r.AddPeer(key, []netip.Prefix{mustPrefix(t, "10.0.0.0/8")})
	if !errors.Is(err, ErrNotIPv6) {
		t.Fatalf("ErrNotIPv6 kutilgan, olindi: %v", err)
	}
}

func TestAddPeer_RejectsEmptyKey(t *testing.T) {
	r := New()

	if _, err := r.AddPeer(noise.PublicKey{}, nil); err == nil {
		t.Fatal("bo'sh kalit rad etilishi kerak edi")
	}
}

func TestRemovePeer_ClearsRoutesSessionAndIndex(t *testing.T) {
	r := New()
	bob := addPeer(t, r, "bob", "2a0e:1234:2::/64")

	session := establishSession(t)
	r.BindSession(bob, session)

	r.RemovePeer(bob.PublicKey)

	// Marshrut yo'q.
	packet := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:2::5")
	if _, err := r.RouteOutbound(packet); !errors.Is(err, ErrNoRoute) {
		t.Errorf("marshrut qoldi: %v", err)
	}

	// Indeks yo'q — bekor qilingan peer paketlari qabul qilinmasligi kerak.
	if _, _, err := r.SessionFor(session.LocalIndex()); !errors.Is(err, ErrUnknownSession) {
		t.Errorf("indeks qoldi: %v", err)
	}

	// Sessiya tozalangan.
	if bob.Session() != nil {
		t.Error("sessiya tozalanmadi")
	}
}

func TestSessionFor_UnknownIndex(t *testing.T) {
	r := New()

	if _, _, err := r.SessionFor(12345); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("ErrUnknownSession kutilgan, olindi: %v", err)
	}
}

// Rekey paytida qisqa vaqt ikkala sessiya ham qabul qilinishi kerak,
// aks holda yo'ldagi paketlar yo'qoladi (ARCHITECTURE.md §3.5).
func TestBindSession_KeepsOldIndexDuringRekey(t *testing.T) {
	r := New()
	bob := addPeer(t, r, "bob", "2a0e:1234:2::/64")

	old := establishSession(t)
	r.BindSession(bob, old)

	fresh := establishSession(t)
	r.BindSession(bob, fresh)

	// Eski indeks hali topilishi kerak.
	if _, _, err := r.SessionFor(old.LocalIndex()); err != nil {
		t.Errorf("eski indeks yo'qoldi: %v", err)
	}
	if _, _, err := r.SessionFor(fresh.LocalIndex()); err != nil {
		t.Errorf("yangi indeks topilmadi: %v", err)
	}

	// Grace tugagach eski indeks olib tashlanadi.
	r.UnbindSession(old.LocalIndex())
	if _, _, err := r.SessionFor(old.LocalIndex()); !errors.Is(err, ErrUnknownSession) {
		t.Errorf("eski indeks tozalanmadi: %v", err)
	}
}

func TestPeer_AllowedIPsReturnsCopy(t *testing.T) {
	r := New()
	alice := addPeer(t, r, "alice", "2a0e:1234:1::/64")

	got := alice.AllowedIPs()
	got[0] = mustPrefix(t, "::/0")

	// Ichki holat o'zgarmasligi kerak, aks holda tashqi kod
	// xavfsizlik tekshiruvini buzib qo'ya oladi.
	packet := ipv6Packet(t, "2001:db8::1", "2a0e:1234:1::1")
	if err := r.VerifyInbound(alice, packet); !errors.Is(err, ErrSpoofedSource) {
		t.Fatal("AllowedIPs() nusxa emas — tashqaridan o'zgartirib bo'ldi")
	}
}

// establishSession testlar uchun haqiqiy Noise sessiyasi yasaydi.
func establishSession(t *testing.T) *noise.Session {
	t.Helper()

	alice, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	initiator, err := noise.StartInitiator(alice, bob.PublicKey())
	if err != nil {
		t.Fatalf("StartInitiator: %v", err)
	}
	responder, err := noise.StartResponder(bob)
	if err != nil {
		t.Fatalf("StartResponder: %v", err)
	}

	initiation, err := initiator.WriteInitiation()
	if err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	if err := responder.ReadInitiation(initiation); err != nil {
		t.Fatalf("ReadInitiation: %v", err)
	}

	response, _, err := responder.WriteResponse()
	if err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}

	session, err := initiator.ReadResponse(response)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	return session
}
