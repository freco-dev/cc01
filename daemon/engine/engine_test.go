package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/path"
	"github.com/freco-dev/cc01/daemon/router"
	pion "github.com/pion/stun/v3"
)

// node — sinov uchun to'liq jihozlangan mesh a'zosi.
type node struct {
	engine   *Engine
	device   *fakeDevice
	bind     *conn.Bind
	identity *noise.Identity
	prefix   netip.Prefix
}

func newNode(t *testing.T, prefix string) *node {
	t.Helper()

	identity, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	bind, err := conn.Open(0)
	if err != nil {
		t.Fatalf("UDP soket: %v", err)
	}

	device := newFakeDevice()

	e, err := New(Config{
		Identity: identity,
		Device:   device,
		Bind:     bind,
		// Testlarda log shovqin qiladi; xatolar assert orqali ko'rinadi.
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Engine qurilma va soketga egalik qiladi — Close ikkalasini
	// ham yopadi.
	t.Cleanup(func() { _ = e.Close() })

	return &node{
		engine:   e,
		device:   device,
		bind:     bind,
		identity: identity,
		prefix:   netip.MustParsePrefix(prefix),
	}
}

// link ikkala tomonda ham peer yozuvini yaratadi va engine'larni
// ishga tushiradi.
func link(t *testing.T, a, b *node) {
	t.Helper()

	loopback := func(bind *conn.Bind) netip.AddrPort {
		return netip.AddrPortFrom(netip.IPv6Loopback(), bind.Port())
	}

	if _, err := a.engine.AddPeer(b.identity.PublicKey(),
		[]netip.Prefix{b.prefix}, loopback(b.bind)); err != nil {
		t.Fatalf("a.AddPeer: %v", err)
	}
	if _, err := b.engine.AddPeer(a.identity.PublicKey(),
		[]netip.Prefix{a.prefix}, loopback(a.bind)); err != nil {
		t.Fatalf("b.AddPeer: %v", err)
	}

	a.engine.Start()
	b.engine.Start()
}

func ipv6Packet(src, dst string, payload ...byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = 59 // No Next Header
	packet[7] = 64

	copy(packet[8:24], netip.MustParseAddr(src).AsSlice())
	copy(packet[24:40], netip.MustParseAddr(dst).AsSlice())
	copy(packet[40:], payload)

	return packet
}

// expectPacket TUN'ga yozilgan paketni kutadi.
func expectPacket(t *testing.T, n *node, timeout time.Duration) []byte {
	t.Helper()

	select {
	case packet := <-n.device.inbound:
		return packet
	case <-time.After(timeout):
		t.Fatal("paket kelmadi")
		return nil
	}
}

// ═══════════════ To'liq datapath ═══════════════

// Faza 1 ning asosiy mezoni: paket TUN'dan chiqib, shifrlangan holda
// UDP orqali o'tib, ikkinchi nodening TUN'iga yetib borishi.
func TestEngine_PacketTraversesMesh(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	link(t, alice, bob)

	payload := []byte("mesh orqali uchidan uchiga")
	sent := ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", payload...)

	alice.device.inject(sent)

	got := expectPacket(t, bob, 5*time.Second)
	if !bytes.Equal(got[:len(sent)], sent) {
		t.Errorf("paket o'zgargan:\nkutilgan %x\nolindi   %x", sent, got[:len(sent)])
	}
}

func TestEngine_BidirectionalTraffic(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	link(t, alice, bob)

	toBob := ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'a')
	alice.device.inject(toBob)
	expectPacket(t, bob, 5*time.Second)

	toAlice := ipv6Packet("2a0e:1234:2::1", "2a0e:1234:1::1", 'b')
	bob.device.inject(toAlice)

	got := expectPacket(t, alice, 5*time.Second)
	if got[40] != 'b' {
		t.Errorf("javob yuki: %q", got[40])
	}
}

// Handshake tugagunga qadar kelgan paketlar yo'qolmasligi kerak.
func TestEngine_QueuedPacketsFlushAfterHandshake(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	link(t, alice, bob)

	// Sessiya hali yo'q — hammasi navbatga tushadi.
	const total = 5
	for i := range total {
		alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", byte(i)))
	}

	seen := make(map[byte]bool, total)
	deadline := time.After(5 * time.Second)

	for len(seen) < total {
		select {
		case packet := <-bob.device.inbound:
			seen[packet[40]] = true
		case <-deadline:
			t.Fatalf("%d/%d paket yetib keldi", len(seen), total)
		}
	}
}

// Sessiya o'rnatilgach endpoint haqiqiy manzil bilan yangilanadi.
func TestEngine_SessionEstablishesBothSides(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	link(t, alice, bob)

	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'x'))
	expectPacket(t, bob, 5*time.Second)

	peerOnAlice, ok := alice.engine.Router().Peer(bob.identity.PublicKey())
	if !ok {
		t.Fatal("alice bob'ni topa olmadi")
	}
	if peerOnAlice.Session() == nil {
		t.Error("alice tomonda sessiya yo'q")
	}

	peerOnBob, ok := bob.engine.Router().Peer(alice.identity.PublicKey())
	if !ok {
		t.Fatal("bob alice'ni topa olmadi")
	}
	if peerOnBob.Session() == nil {
		t.Error("bob tomonda sessiya yo'q")
	}

	// Bob alice'ning haqiqiy manzilini bilishi kerak.
	endpoint, ok := peerOnBob.Endpoint()
	if !ok || endpoint.Port() != alice.bind.Port() {
		t.Errorf("bob'dagi endpoint: %v (kutilgan port %d)", endpoint, alice.bind.Port())
	}
}

// ═══════════════ Xavfsizlik ═══════════════

// Mallory — tarmoqning qonuniy a'zosi, lekin Alice'ning manzilidan
// yozmoqchi. Datapath uni to'sishi shart (ARCHITECTURE.md §4.2).
func TestEngine_SpoofedPacketNeverReachesTUN(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	mallory := newNode(t, "2a0e:1234:99::/64")

	link(t, alice, bob)
	link(t, mallory, bob)

	// Avval qonuniy paket — sessiya o'rnatilsin.
	mallory.device.inject(ipv6Packet("2a0e:1234:99::1", "2a0e:1234:2::1", 'o'))
	if got := expectPacket(t, bob, 5*time.Second); got[40] != 'o' {
		t.Fatalf("qonuniy paket yetib kelmadi: %q", got[40])
	}

	// Endi Alice'ning manzilidan.
	mallory.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'x'))

	select {
	case packet := <-bob.device.inbound:
		t.Fatalf("SOXTALASHTIRILGAN PAKET TUN'GA YETIB BORDI: %x", packet[:48])
	case <-time.After(time.Second):
		// To'g'ri: paket tashlandi.
	}
}

// Ro'yxatdan o'tmagan node handshake qila olmasligi kerak.
func TestEngine_UnknownPeerHandshakeRejected(t *testing.T) {
	bob := newNode(t, "2a0e:1234:2::/64")
	stranger := newNode(t, "2a0e:1234:88::/64")

	// Faqat stranger bob'ni biladi; bob stranger'ni bilmaydi.
	if _, err := stranger.engine.AddPeer(bob.identity.PublicKey(),
		[]netip.Prefix{bob.prefix},
		netip.AddrPortFrom(netip.IPv6Loopback(), bob.bind.Port())); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	bob.engine.Start()
	stranger.engine.Start()

	stranger.device.inject(ipv6Packet("2a0e:1234:88::1", "2a0e:1234:2::1", 'x'))

	select {
	case packet := <-bob.device.inbound:
		t.Fatalf("noma'lum peer paketi qabul qilindi: %x", packet[:48])
	case <-time.After(time.Second):
	}

	peer, _ := stranger.engine.Router().Peer(bob.identity.PublicKey())
	if peer.Session() != nil {
		t.Error("noma'lum peer bilan sessiya o'rnatildi")
	}
}

// Marshrut yo'q bo'lsa paket jimgina tashlanishi kerak — engine
// yiqilmasligi yoki bloklanmasligi kerak.
func TestEngine_UnroutablePacketDropped(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	link(t, alice, bob)

	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2001:db8::1", 'x'))

	select {
	case <-bob.device.inbound:
		t.Fatal("marshrutsiz paket yuborildi")
	case <-time.After(500 * time.Millisecond):
	}

	// Engine hali ishlashda davom etishi kerak.
	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'y'))
	if got := expectPacket(t, bob, 5*time.Second); got[40] != 'y' {
		t.Errorf("keyingi paket: %q", got[40])
	}
}

// ═══════════════ Hayot sikli ═══════════════

func TestEngine_RequiresConfiguration(t *testing.T) {
	identity, _ := noise.GenerateIdentity()
	bind, _ := conn.Open(0)
	defer bind.Close()

	cases := []struct {
		name string
		cfg  Config
	}{
		{"identity yo'q", Config{Device: newFakeDevice(), Bind: bind}},
		{"qurilma yo'q", Config{Identity: identity, Bind: bind}},
		{"soket yo'q", Config{Identity: identity, Device: newFakeDevice()}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Error("xato kutilgan edi")
			}
		})
	}
}

func TestEngine_CloseIsIdempotent(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	alice.engine.Start()

	if err := alice.engine.Close(); err != nil {
		t.Fatalf("birinchi Close: %v", err)
	}
	if err := alice.engine.Close(); err != nil {
		t.Errorf("ikkinchi Close: %v", err)
	}
}

func TestEngine_StartIsIdempotent(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")

	alice.engine.Start()
	alice.engine.Start()

	// Ikki marta Start goroutine'larni ikkilantirmasligi kerak —
	// Close muammosiz tugashi buni ko'rsatadi.
	if err := alice.engine.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestEngine_PeerRemovalStopsTraffic(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	link(t, alice, bob)

	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'x'))
	expectPacket(t, bob, 5*time.Second)

	bob.engine.Router().RemovePeer(alice.identity.PublicKey())

	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'y'))

	select {
	case packet := <-bob.device.inbound:
		t.Fatalf("o'chirilgan peerdan paket keldi: %q", packet[40])
	case <-time.After(time.Second):
	}
}

var _ = router.ErrNoRoute // paket ishlatilganini bildirish

// Regressiya: keepalive'da ichki paket yo'q, shuning uchun uni
// cryptokey routing tekshiruvidan o'tkazish "soxtalashtirish"
// ogohlantirishini keltirib chiqarardi. Soxta signallar operatorni
// haqiqiy ogohlantirishlarga befarq qilib qo'yadi.
func TestEngine_KeepaliveDoesNotTriggerSpoofWarning(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")

	// Log'ni ushlab, ogohlantirishlarni tekshiramiz.
	var captured logCapture
	alice.engine.log = slog.New(&captured)
	bob.engine.log = slog.New(&captured)

	link(t, alice, bob)

	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'x'))
	expectPacket(t, bob, 5*time.Second)

	// Keepalive'ni qo'lda yuboramiz (taymer 25 s kutmaslik uchun).
	peer, ok := alice.engine.Router().Peer(bob.identity.PublicKey())
	if !ok {
		t.Fatal("peer topilmadi")
	}
	packet, err := peer.Session().Seal(noise.TypeKeepalive, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := alice.engine.send(peer, packet); err != nil {
		t.Fatalf("send: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	if captured.sawSpoofWarning() {
		t.Error("keepalive soxtalashtirish ogohlantirishini keltirib chiqardi")
	}

	// Keepalive'dan keyin oddiy trafik ishlashda davom etishi kerak.
	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'z'))
	if got := expectPacket(t, bob, 5*time.Second); got[40] != 'z' {
		t.Errorf("keepalive'dan keyingi paket: %q", got[40])
	}
}

// logCapture ogohlantirishlarni yig'adi.
type logCapture struct {
	mu       sync.Mutex
	warnings []string
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, record slog.Record) error {
	if record.Level < slog.LevelWarn {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warnings = append(c.warnings, record.Message)
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

func (c *logCapture) sawSpoofWarning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, message := range c.warnings {
		if strings.Contains(message, "SOXTALASHTIRILGAN") {
			return true
		}
	}
	return false
}

// STUN javoblari datapath bilan bir xil soketga keladi. Ular
// bir-birini buzmasligi kerak: STUN paketlari cc01 sifatida
// parse qilinmasin, cc01 paketlari esa STUN klienti tomonidan
// yutib yuborilmasin.
func TestEngine_StunSharesSocketWithDatapath(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	link(t, alice, bob)

	stunServer := startTestStunServer(t)

	// Avval trafik oqsin — sessiya o'rnatilsin.
	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'a'))
	expectPacket(t, bob, 5*time.Second)

	// Endi o'sha soketdan STUN so'raymiz.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	mapped, err := alice.engine.DiscoverPublicEndpoint(ctx, stunServer)
	if err != nil {
		t.Fatalf("DiscoverPublicEndpoint: %v", err)
	}

	// STUN server bizning soketimizning manzilini ko'rishi kerak.
	if mapped.Port() != alice.bind.Port() {
		t.Errorf("port %d kutilgan, %d olindi", alice.bind.Port(), mapped.Port())
	}

	// STUN'dan keyin datapath ishlashda davom etishi kerak.
	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'b'))
	if got := expectPacket(t, bob, 5*time.Second); got[40] != 'b' {
		t.Errorf("STUN'dan keyingi paket: %q", got[40])
	}
}

// startTestStunServer minimal STUN javob beruvchi ishga tushiradi.
func startTestStunServer(t *testing.T) netip.AddrPort {
	t.Helper()

	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("STUN soketi: %v", err)
	}
	t.Cleanup(func() { _ = socket.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := socket.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}

			request := &pion.Message{Raw: append([]byte(nil), buf[:n]...)}
			if request.Decode() != nil {
				continue
			}

			response, err := pion.Build(request, pion.BindingSuccess,
				&pion.XORMappedAddress{
					IP:   net.IP(from.Addr().AsSlice()),
					Port: int(from.Port()),
				})
			if err != nil {
				continue
			}
			_, _ = socket.WriteToUDPAddrPort(response.Raw, from)
		}
	}()

	return socket.LocalAddr().(*net.UDPAddr).AddrPort()
}

// ═══════════════ Yo'l tanlash ═══════════════

// Probe javoblari kelgach to'g'ridan-to'g'ri yo'l tasdiqlanishi kerak
// (ADR-005 dagi "P2P-upgrade" qismi).
func TestEngine_ConfirmsDirectPathThroughProbes(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	link(t, alice, bob)

	// Sessiya o'rnatilsin.
	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'x'))
	expectPacket(t, bob, 5*time.Second)

	// Probe'lar taymer orqali yuboriladi; UpgradeSamples ta javob
	// kerak.
	deadline := time.After(15 * time.Second)
	for {
		state, rtt, ok := alice.engine.PathState(bob.identity.PublicKey())
		if ok && state == path.StateDirectActive {
			if rtt <= 0 {
				t.Errorf("RTT o'lchanishi kerak edi: %v", rtt)
			}
			return
		}

		select {
		case <-deadline:
			t.Fatalf("to'g'ridan-to'g'ri yo'l tasdiqlanmadi: %v", state)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Disco paketlari TUN'ga chiqmasligi kerak — ular yo'l o'lchash
// uchun, foydali yuk emas.
func TestEngine_DiscoPacketsDoNotReachTUN(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	link(t, alice, bob)

	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'x'))

	// Birinchi paket — bizniki.
	if got := expectPacket(t, bob, 5*time.Second); got[40] != 'x' {
		t.Fatalf("kutilmagan paket: %q", got[40])
	}

	// Probe'lar oqib turgan bo'lsa ham TUN'ga boshqa hech narsa
	// chiqmasligi kerak.
	select {
	case packet := <-bob.device.inbound:
		t.Fatalf("TUN'ga ortiqcha paket chiqdi: %x", packet[:min(48, len(packet))])
	case <-time.After(2 * time.Second):
	}
}

// Yo'l holati `cc01 status` uchun ochiq bo'lishi kerak.
func TestEngine_ReportsPathState(t *testing.T) {
	alice := newNode(t, "2a0e:1234:1::/64")
	bob := newNode(t, "2a0e:1234:2::/64")
	link(t, alice, bob)

	// Noma'lum peer uchun holat bo'lmasligi kerak.
	var unknown noise.PublicKey
	unknown[0] = 0xaa
	if _, _, ok := alice.engine.PathState(unknown); ok {
		t.Error("noma'lum peer uchun holat qaytarildi")
	}

	alice.device.inject(ipv6Packet("2a0e:1234:1::1", "2a0e:1234:2::1", 'x'))
	expectPacket(t, bob, 5*time.Second)

	if _, _, ok := alice.engine.PathState(bob.identity.PublicKey()); !ok {
		t.Error("peer uchun holat kutilgan edi")
	}
}
