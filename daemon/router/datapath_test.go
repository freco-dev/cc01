package router

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/freco-dev/cc01/daemon/noise"
)

// node — test uchun bitta mesh a'zosi: kalitlari, routeri va o'z manzili.
type node struct {
	identity *noise.Identity
	router   *Router
	prefix   netip.Prefix
}

func newNode(t *testing.T, prefix string) *node {
	t.Helper()

	identity, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return &node{identity: identity, router: New(), prefix: mustPrefix(t, prefix)}
}

// connect ikkita node o'rtasida to'liq handshake bajaradi va ikkala
// tomonda ham peer + sessiya sozlaydi.
func connect(t *testing.T, a, b *node) (peerAB, peerBA *Peer) {
	t.Helper()

	peerAB, err := a.router.AddPeer(b.identity.PublicKey(), []netip.Prefix{b.prefix})
	if err != nil {
		t.Fatalf("a.AddPeer: %v", err)
	}
	peerBA, err = b.router.AddPeer(a.identity.PublicKey(), []netip.Prefix{a.prefix})
	if err != nil {
		t.Fatalf("b.AddPeer: %v", err)
	}

	initiator, err := noise.StartInitiator(a.identity, b.identity.PublicKey())
	if err != nil {
		t.Fatalf("StartInitiator: %v", err)
	}
	responder, err := noise.StartResponder(b.identity)
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

	response, sessionB, err := responder.WriteResponse()
	if err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	sessionA, err := initiator.ReadResponse(response)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	a.router.BindSession(peerAB, sessionA)
	b.router.BindSession(peerBA, sessionB)

	return peerAB, peerBA
}

// send to'liq chiqish yo'lini bajaradi: marshrutlash → shifrlash.
func (n *node) send(t *testing.T, packet []byte) []byte {
	t.Helper()

	peer, err := n.router.RouteOutbound(packet)
	if err != nil {
		t.Fatalf("RouteOutbound: %v", err)
	}

	sealed, err := peer.Session().Seal(noise.TypeData, packet)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}

// receive to'liq kirish yo'lini bajaradi: sessiya → deshifrlash →
// CRYPTOKEY ROUTING.
func (n *node) receive(wire []byte) ([]byte, error) {
	header, err := noise.ParseHeader(wire)
	if err != nil {
		return nil, err
	}

	peer, session, err := n.router.SessionFor(header.ReceiverIndex)
	if err != nil {
		return nil, err
	}

	_, inner, err := session.Open(wire)
	if err != nil {
		return nil, err
	}

	// Deshifrlangan har bir paket uchun, ISTISNOSIZ.
	if err := n.router.VerifyInbound(peer, inner); err != nil {
		return nil, err
	}

	return inner, nil
}

// To'liq datapath: A dan B ga shifrlangan paket.
func TestDatapath_EndToEnd(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	connect(t, alice, bob)

	payload := []byte("mesh orqali salom")
	packet := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:2::1", payload...)

	wire := alice.send(t, packet)
	if bytes.Contains(wire, payload) {
		t.Fatal("ochiq matn simda ko'rinib turibdi")
	}

	got, err := bob.receive(wire)
	if err != nil {
		t.Fatalf("qabul qilish: %v", err)
	}
	if !bytes.Equal(got, packet) {
		t.Error("paket o'zgargan")
	}
}

func TestDatapath_BidirectionalTraffic(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	connect(t, alice, bob)

	toBob := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:2::1", 'a')
	if _, err := bob.receive(alice.send(t, toBob)); err != nil {
		t.Fatalf("A→B: %v", err)
	}

	toAlice := ipv6Packet(t, "2a0e:1234:2::1", "2a0e:1234:1::1", 'b')
	if _, err := alice.receive(bob.send(t, toAlice)); err != nil {
		t.Fatalf("B→A: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════
// Asosiy hujum stsenariysi (§7.1 majburiy stsenariy 4).
//
// Mallory — tarmoqning QONUNIY a'zosi: uning kalitlari haqiqiy va
// Noise handshake'i muvaffaqiyatli o'tadi. U Alice'ning manzilidan
// paket yuborib, Bob'ni aldashga urinadi.
//
// Noise sessiyasi paket AYNAN MALLORY'DAN kelganini isbotlaydi, lekin
// ichidagi manba manzilini tekshirmaydi. Uni faqat cryptokey routing
// to'sadi.
// ═══════════════════════════════════════════════════════════════
func TestDatapath_LegitimatePeerCannotSpoofAnother(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	mallory := newNode(t, "2a0e:1234:99::/64")

	connect(t, alice, bob)
	connect(t, mallory, bob)

	// Mallory Alice'ning manzilidan yozadi.
	spoofed := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:2::1", 'x')

	// U o'z sessiyasidan foydalanadi — bu butunlay qonuniy.
	peer, err := mallory.router.Peer(bob.identity.PublicKey())
	if !err {
		t.Fatal("mallory bob'ni topa olmadi")
	}
	wire, sealErr := peer.Session().Seal(noise.TypeData, spoofed)
	if sealErr != nil {
		t.Fatalf("Seal: %v", sealErr)
	}

	// Bob paketni deshifrlay oladi — kripto to'g'ri. Lekin
	// cryptokey routing uni to'sishi SHART.
	_, receiveErr := bob.receive(wire)
	if !errors.Is(receiveErr, ErrSpoofedSource) {
		t.Fatalf("SOXTALASHTIRISH O'TIB KETDI: %v", receiveErr)
	}
}

// Mallory o'z manzilidan yozsa — hammasi joyida.
func TestDatapath_LegitimatePeerOwnAddressAccepted(t *testing.T) {
	bob := newNode(t, "2a0e:1234:2::/64")
	mallory := newNode(t, "2a0e:1234:99::/64")
	connect(t, mallory, bob)

	packet := ipv6Packet(t, "2a0e:1234:99::1", "2a0e:1234:2::1", 'x')

	if _, err := bob.receive(mallory.send(t, packet)); err != nil {
		t.Fatalf("o'z manzilidan kelgan paket rad etildi: %v", err)
	}
}

// Peer bekor qilingach uning paketlari darhol to'xtashi kerak.
func TestDatapath_RevokedPeerIsCutOff(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	connect(t, alice, bob)

	packet := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:2::1", 'x')
	wire := alice.send(t, packet)

	bob.router.RemovePeer(alice.identity.PublicKey())

	if _, err := bob.receive(wire); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("bekor qilingan peer paketi qabul qilindi: %v", err)
	}
}

// Simdagi paket takrorlansa replay oynasi to'sadi.
func TestDatapath_ReplayIsRejected(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	connect(t, alice, bob)

	packet := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:2::1", 'x')
	wire := alice.send(t, packet)

	if _, err := bob.receive(bytes.Clone(wire)); err != nil {
		t.Fatalf("birinchi paket: %v", err)
	}
	if _, err := bob.receive(wire); !errors.Is(err, noise.ErrReplay) {
		t.Fatalf("takroriy paket qabul qilindi: %v", err)
	}
}

// Uch node: A→B va A→C bir vaqtda, har biri o'z sessiyasi bilan.
func TestDatapath_MultiplePeers(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	carol := newNode(t, "2a0e:1234:3::/64")

	connect(t, alice, bob)
	connect(t, alice, carol)

	toBob := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:2::1", 'b')
	toCarol := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:3::1", 'c')

	if _, err := bob.receive(alice.send(t, toBob)); err != nil {
		t.Errorf("A→B: %v", err)
	}
	if _, err := carol.receive(alice.send(t, toCarol)); err != nil {
		t.Errorf("A→C: %v", err)
	}

	// Bob uchun mo'ljallangan paketni Carol ocha olmasligi kerak.
	if _, err := carol.receive(alice.send(t, toBob)); err == nil {
		t.Error("Carol Bob'ning paketini ochdi")
	}
}

func BenchmarkDatapath_SendReceive(b *testing.B) {
	t := &testing.T{}
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	connect(t, alice, bob)

	payload := make([]byte, 1280-ipv6HeaderLen)
	packet := ipv6Packet(t, "2a0e:1234:1::1", "2a0e:1234:2::1", payload...)

	peer, _ := alice.router.Peer(bob.identity.PublicKey())

	b.SetBytes(int64(len(packet)))
	for b.Loop() {
		wire, err := peer.Session().Seal(noise.TypeData, packet)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := bob.receive(wire); err != nil {
			b.Fatal(err)
		}
	}
}
