package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/noise"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startRelay(t *testing.T) *Server {
	t.Helper()

	identity, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	bind, err := conn.Open(0)
	if err != nil {
		t.Fatalf("soket: %v", err)
	}

	server, err := NewServer(Options{Identity: identity, Bind: bind, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go server.Serve()
	t.Cleanup(func() { _ = server.Close() })

	return server
}

// testNode — relayga ulanuvchi klient, o'z soketi va o'quvchisi bilan.
type testNode struct {
	identity *noise.Identity
	client   *Client
	bind     *conn.Bind
	received chan *Received
}

func newNode(t *testing.T, server *Server) *testNode {
	t.Helper()

	identity, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return newNodeWithIdentity(t, server, identity)
}

// newNodeWithIdentity — berilgan kalit bilan, YANGI soketda.
func newNodeWithIdentity(t *testing.T, server *Server, identity *noise.Identity) *testNode {
	t.Helper()

	bind, err := conn.Open(0)
	if err != nil {
		t.Fatalf("soket: %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })

	relayAddr := netip.AddrPortFrom(netip.IPv6Loopback(), server.Addr().Port())

	client, err := NewClient(ClientOptions{
		Identity: identity,
		RelayKey: server.PublicKey(),
		Endpoint: relayAddr,
		Send:     bind.Send,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	node := &testNode{
		identity: identity,
		client:   client,
		bind:     bind,
		received: make(chan *Received, 16),
	}

	// Datapath o'quvchisini taqlid qilamiz: kelgan paketlarni
	// relay klientiga uzatamiz.
	go func() {
		messages := conn.NewDatagrams(8, 2048)
		for {
			for i := range messages {
				messages[i].Payload = messages[i].Payload[:cap(messages[i].Payload)]
			}

			count, err := bind.Receive(messages)
			if err != nil {
				return
			}
			for i := range count {
				if packet, mine := client.Handle(messages[i].Payload, messages[i].From); mine && packet != nil {
					select {
					case node.received <- packet:
					default:
					}
				}
			}
		}
	}()

	return node
}

func (n *testNode) connect(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	if err := n.client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
}

func (n *testNode) expect(t *testing.T, timeout time.Duration) *Received {
	t.Helper()

	select {
	case packet := <-n.received:
		return packet
	case <-time.After(timeout):
		t.Fatal("paket kelmadi")
		return nil
	}
}

// ═══════════════ Asosiy oqim ═══════════════

func TestRelay_ForwardsBetweenNodes(t *testing.T) {
	server := startRelay(t)

	alice := newNode(t, server)
	bob := newNode(t, server)

	alice.connect(t)
	bob.connect(t)

	if server.Sessions() != 2 {
		t.Fatalf("2 sessiya kutilgan, %d olindi", server.Sessions())
	}

	payload := []byte("peerlar o'rtasidagi shifrlangan yuk")
	if err := alice.client.Send(bob.client.NodeID(), payload); err != nil {
		t.Fatalf("Send: %v", err)
	}

	got := bob.expect(t, 5*time.Second)

	if !bytes.Equal(got.Inner, payload) {
		t.Errorf("yuk o'zgargan: %q", got.Inner)
	}
	if got.From != alice.client.NodeID() {
		t.Errorf("jo'natuvchi: %s kutilgan, %s olindi",
			alice.client.NodeID().Short(), got.From.Short())
	}
}

func TestRelay_Bidirectional(t *testing.T) {
	server := startRelay(t)

	alice := newNode(t, server)
	bob := newNode(t, server)
	alice.connect(t)
	bob.connect(t)

	if err := alice.client.Send(bob.client.NodeID(), []byte("a→b")); err != nil {
		t.Fatalf("a→b: %v", err)
	}
	if got := bob.expect(t, 5*time.Second); string(got.Inner) != "a→b" {
		t.Errorf("a→b: %q", got.Inner)
	}

	if err := bob.client.Send(alice.client.NodeID(), []byte("b→a")); err != nil {
		t.Fatalf("b→a: %v", err)
	}
	if got := alice.expect(t, 5*time.Second); string(got.Inner) != "b→a" {
		t.Errorf("b→a: %q", got.Inner)
	}
}

// ═══════════════ Xavfsizlik ═══════════════

// Relayning asosiy kafolati: u faqat node_id ni ko'radi, foydali
// yukni ocha OLMAYDI (ARCHITECTURE.md §5.1 dagi kompromis radiusi).
func TestRelay_CannotReadInnerPayload(t *testing.T) {
	server := startRelay(t)

	alice := newNode(t, server)
	bob := newNode(t, server)
	alice.connect(t)
	bob.connect(t)

	// Ichki paket peerlar o'rtasida shifrlangan bo'ladi. Uni taqlid
	// qilish uchun alohida Noise sessiyasidan foydalanamiz.
	secret := []byte("MAXFIY-YUK-RELAY-KO'RMASLIGI-KERAK")
	sealed := sealBetweenPeers(t, secret)

	if err := alice.client.Send(bob.client.NodeID(), sealed); err != nil {
		t.Fatalf("Send: %v", err)
	}

	got := bob.expect(t, 5*time.Second)

	// Relay uzatdi, lekin ochmadi: uzatilgan baytlar o'zgarmagan va
	// ochiq matn ularda yo'q.
	if !bytes.Equal(got.Inner, sealed) {
		t.Error("uzatilgan paket o'zgargan")
	}
	if bytes.Contains(got.Inner, secret) {
		t.Fatal("ochiq matn ko'rinib turibdi")
	}
}

// Klient jo'natuvchi sifatida boshqa nodeni ko'rsata olmasligi kerak —
// relay bu qiymatni O'Z sessiyasidan oladi.
func TestRelay_SenderIdentityCannotBeForged(t *testing.T) {
	server := startRelay(t)

	alice := newNode(t, server)
	bob := newNode(t, server)
	mallory := newNode(t, server)
	alice.connect(t)
	bob.connect(t)
	mallory.connect(t)

	if err := mallory.client.Send(bob.client.NodeID(), []byte("aldov")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	got := bob.expect(t, 5*time.Second)

	if got.From == alice.client.NodeID() {
		t.Fatal("JO'NATUVCHI SOXTALASHTIRILDI")
	}
	if got.From != mallory.client.NodeID() {
		t.Errorf("mallory kutilgan, %s olindi", got.From.Short())
	}
}

// Ulanmagan qabul qiluvchiga yuborilgan paket jimgina tashlanadi —
// bu odatiy hol, relay yiqilmasligi kerak.
func TestRelay_DropsForUnknownDestination(t *testing.T) {
	server := startRelay(t)

	alice := newNode(t, server)
	alice.connect(t)

	var unknown NodeID
	unknown[0] = 0xff

	if err := alice.client.Send(unknown, []byte("hech kimga")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	_, dropped, _ := server.Stats()
	if dropped == 0 {
		t.Error("paket tashlangan deb qayd etilmadi")
	}

	// Relay ishlashda davom etishi kerak.
	bob := newNode(t, server)
	bob.connect(t)

	if err := alice.client.Send(bob.client.NodeID(), []byte("ishlayapti")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := bob.expect(t, 5*time.Second); string(got.Inner) != "ishlayapti" {
		t.Errorf("%q", got.Inner)
	}
}

func TestRelay_RejectsGarbage(t *testing.T) {
	server := startRelay(t)

	sender, err := conn.Open(0)
	if err != nil {
		t.Fatalf("soket: %v", err)
	}
	defer sender.Close()

	target := netip.AddrPortFrom(netip.IPv6Loopback(), server.Addr().Port())

	for _, junk := range [][]byte{
		[]byte("salom"),
		make([]byte, 1),
		make([]byte, 300),
	} {
		if err := sender.Send(junk, target); err != nil {
			t.Fatalf("yuborish: %v", err)
		}
	}

	time.Sleep(300 * time.Millisecond)

	// Server hali ishlashi kerak.
	alice := newNode(t, server)
	alice.connect(t)
}

// ═══════════════ Sessiya hayot sikli ═══════════════

func TestClient_SendBeforeConnect(t *testing.T) {
	server := startRelay(t)
	alice := newNode(t, server)

	var target NodeID
	if err := alice.client.Send(target, []byte("erta")); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("ErrNotConnected kutilgan, olindi: %v", err)
	}
}

// Node qayta ulanganda relay eski sessiyani almashtirishi kerak,
// aks holda eski indeks xotirada abadiy qolardi.
//
// Test ATAYLAB yangi soket ishlatadi: bitta soketda ikkita o'quvchi
// bo'lsa ular paketlar uchun poyga qiladi — bu aynan STUN'da tuzatgan
// muammo.
func TestClient_ReconnectReplacesSession(t *testing.T) {
	server := startRelay(t)

	first := newNode(t, server)
	first.connect(t)

	firstIndex, ok := first.client.LocalIndex()
	if !ok {
		t.Fatal("birinchi sessiya indeksi yo'q")
	}

	// O'sha node, boshqa soketdan qayta ulanadi.
	second := newNodeWithIdentity(t, server, first.identity)
	second.connect(t)

	secondIndex, ok := second.client.LocalIndex()
	if !ok {
		t.Fatal("ikkinchi sessiya indeksi yo'q")
	}
	if firstIndex == secondIndex {
		t.Error("qayta ulanishda yangi sessiya kutilgan edi")
	}

	// Relayda bitta node uchun bitta sessiya qolishi kerak.
	if server.Sessions() != 1 {
		t.Errorf("1 sessiya kutilgan, %d olindi", server.Sessions())
	}

	// Yangi sessiya orqali trafik oqishi kerak.
	bob := newNode(t, server)
	bob.connect(t)

	if err := second.client.Send(bob.client.NodeID(), []byte("qayta ulandi")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := bob.expect(t, 5*time.Second); string(got.Inner) != "qayta ulandi" {
		t.Errorf("%q", got.Inner)
	}
}

func TestServer_Close(t *testing.T) {
	identity, _ := noise.GenerateIdentity()
	bind, _ := conn.Open(0)

	server, err := NewServer(Options{Identity: identity, Bind: bind, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go server.Serve()

	if err := server.Close(); err != nil {
		t.Fatalf("birinchi Close: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Errorf("ikkinchi Close: %v", err)
	}
}

func TestNewServer_Validation(t *testing.T) {
	identity, _ := noise.GenerateIdentity()
	bind, _ := conn.Open(0)
	defer bind.Close()

	if _, err := NewServer(Options{Bind: bind}); err == nil {
		t.Error("identity'siz xato kutilgan edi")
	}
	if _, err := NewServer(Options{Identity: identity}); err == nil {
		t.Error("soketsiz xato kutilgan edi")
	}
}

func TestNewClient_Validation(t *testing.T) {
	identity, _ := noise.GenerateIdentity()
	valid := netip.MustParseAddrPort("[::1]:1234")
	send := func([]byte, netip.AddrPort) error { return nil }

	cases := []struct {
		name string
		opts ClientOptions
	}{
		{"identity yo'q", ClientOptions{RelayKey: identity.PublicKey(), Endpoint: valid, Send: send}},
		{"relay kaliti yo'q", ClientOptions{Identity: identity, Endpoint: valid, Send: send}},
		{"endpoint yaroqsiz", ClientOptions{Identity: identity, RelayKey: identity.PublicKey(), Send: send}},
		{"send yo'q", ClientOptions{Identity: identity, RelayKey: identity.PublicKey(), Endpoint: valid}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewClient(tc.opts); err == nil {
				t.Error("xato kutilgan edi")
			}
		})
	}
}

// sealBetweenPeers ikki peer o'rtasida shifrlangan paket yasaydi —
// relay uni ocha olmasligi kerak.
func sealBetweenPeers(t *testing.T, payload []byte) []byte {
	t.Helper()

	alice, _ := noise.GenerateIdentity()
	bob, _ := noise.GenerateIdentity()

	initiator, err := noise.StartInitiator(alice, bob.PublicKey())
	if err != nil {
		t.Fatalf("StartInitiator: %v", err)
	}
	responder, err := noise.StartResponder(bob)
	if err != nil {
		t.Fatalf("StartResponder: %v", err)
	}

	initiation, _ := initiator.WriteInitiation()
	_ = responder.ReadInitiation(initiation)
	response, _, _ := responder.WriteResponse()

	session, err := initiator.ReadResponse(response)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	sealed, err := session.Seal(noise.TypeData, payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return sealed
}
