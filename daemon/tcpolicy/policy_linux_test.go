//go:build linux

package tcpolicy

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/freco-dev/cc01/daemon/tun"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// Bu testlar HAQIQIY TUN qurilmasi yaratadi va unga paket yozadi.
//
// TUN fd'ga yozilgan paket yadro uchun qurilmaga KELGAN paket, ya'ni
// u tc ingress yo'lidan o'tadi — aynan bizga kerak bo'lgan nuqta.
//
// Ishga tushirish: make bpf-verify
func requireKernel(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("tc dasturini yuklash uchun root kerak")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun mavjud emas: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("memlock chegarasini olib bo'lmadi: %v", err)
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const (
	localAddr = "fd00:cc01:7c01::1"
	peerAddr  = "fd00:cc01:7c01::2"
	testNet   = "fd00:cc01:7c01::/64"
)

// testDevice sinov uchun TUN qurilmasini yaratadi.
func testDevice(t *testing.T) *tun.Device {
	t.Helper()

	device, err := tun.Create(tun.Config{
		Name:      "cc0pol",
		Addresses: []netip.Prefix{netip.MustParsePrefix(localAddr + "/128")},
		Routes:    []netip.Prefix{netip.MustParsePrefix(testNet)},
	})
	if err != nil {
		t.Skipf("TUN yaratilmadi: %v", err)
	}

	t.Cleanup(func() { _ = device.Close() })
	return device
}

// echoRequest peerdan bizga ICMPv6 echo so'rovi yasaydi.
func echoRequest(t *testing.T, seq int) []byte {
	t.Helper()

	src := netip.MustParseAddr(peerAddr)
	dst := netip.MustParseAddr(localAddr)

	body := &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: seq, Data: []byte("cc01-policy")}
	payload, err := (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: body}).
		Marshal(icmp.IPv6PseudoHeader(src.AsSlice(), dst.AsSlice()))
	if err != nil {
		t.Fatalf("ICMPv6: %v", err)
	}

	packet := make([]byte, 40+len(payload))
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = 58 // ICMPv6
	packet[7] = 64
	copy(packet[8:24], src.AsSlice())
	copy(packet[24:40], dst.AsSlice())
	copy(packet[40:], payload)

	return packet
}

// inject paketni TUN'ga yozadi — yadro uchun bu kelgan paket.
func inject(t *testing.T, device *tun.Device, packet []byte) {
	t.Helper()

	buf := make([]byte, tun.Offset+len(packet))
	copy(buf[tun.Offset:], packet)

	if _, err := device.Write([][]byte{buf}, tun.Offset); err != nil {
		t.Fatalf("TUN'ga yozish: %v", err)
	}
}

// Verifier tc dasturini qabul qilishi kerak.
func TestXDPPolicy_LoadsAndAttaches(t *testing.T) {
	requireKernel(t)
	device := testDevice(t)

	filter, err := Load(Config{Interface: device.Name(), Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()
}

// L2 qurilmaga biriktirish RAD ETILISHI kerak: dastur paketni
// Ethernet sarlavhasisiz o'qiydi va L2 qurilmada u baytlarni
// jimgina noto'g'ri talqin qilardi.
func TestXDPPolicy_RejectsLayer2Interface(t *testing.T) {
	requireKernel(t)

	// `lo` da MAC bor (nol bo'lsa ham uzunligi 6) — L2 hisoblanadi.
	_, err := Load(Config{Interface: "lo", Logger: quiet()})
	if err == nil {
		t.Fatal("L2 interfeys qabul qilindi")
	}
}

// Deny-by-default: qoida yozilmagan bo'lsa paket tashlanishi kerak.
func TestXDPPolicy_DeniesByDefault(t *testing.T) {
	requireKernel(t)
	device := testDevice(t)

	filter, err := Load(Config{Interface: device.Name(), Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	inject(t, device, echoRequest(t, 1))
	time.Sleep(100 * time.Millisecond)

	stats, err := filter.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}

	if stats[StatDrop] == 0 {
		t.Fatalf("qoidasiz paket tashlanmadi (jami=%d ruxsat=%d)",
			stats[StatTotal], stats[StatAllow])
	}
	if stats[StatNoRule] == 0 {
		t.Error("'qoida topilmadi' hisoblagichi to'ldirilmadi")
	}
}

// Qoida qo'shilgach paket o'tishi kerak.
func TestXDPPolicy_AllowsMatchingRule(t *testing.T) {
	requireKernel(t)
	device := testDevice(t)

	filter, err := Load(Config{Interface: device.Name(), Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	const identity = 42

	if err := filter.SetIdentity(netip.MustParsePrefix(peerAddr+"/128"), identity); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}

	// ICMPv6 (58) uchun istalgan portga ruxsat.
	rule := Rule{Identity: identity, Proto: 58, Verdict: Allow, RuleID: 7}
	if err := filter.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	inject(t, device, echoRequest(t, 2))
	time.Sleep(100 * time.Millisecond)

	stats, err := filter.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats[StatAllow] == 0 {
		t.Fatalf("qoidaga mos paket o'tkazilmadi (tashlangan=%d)", stats[StatDrop])
	}

	hits, found, err := filter.Hits(rule)
	if err != nil || !found {
		t.Fatalf("qoida yozuvi: found=%v err=%v", found, err)
	}
	if hits == 0 {
		t.Error("qoida hisoblagichi to'ldirilmadi")
	}
}

// Uzunroq prefiks ustunlik qilishi kerak (longest-prefix match).
//
// Busiz "hammaga taqiq, bittasiga ruxsat" qoidasini yozib
// bo'lmasdi — eng muhim naqshlardan biri.
func TestXDPPolicy_LongestPrefixWins(t *testing.T) {
	requireKernel(t)
	device := testDevice(t)

	filter, err := Load(Config{Interface: device.Name(), Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	// Butun tarmoq — taqiqlangan guruh.
	if err := filter.SetIdentity(netip.MustParsePrefix(testNet), 1); err != nil {
		t.Fatalf("SetIdentity(/64): %v", err)
	}
	// Aniq bitta node — ruxsat etilgan guruh.
	if err := filter.SetIdentity(netip.MustParsePrefix(peerAddr+"/128"), 2); err != nil {
		t.Fatalf("SetIdentity(/128): %v", err)
	}

	if err := filter.AddRule(Rule{Identity: 1, Verdict: Drop}); err != nil {
		t.Fatalf("AddRule(drop): %v", err)
	}
	if err := filter.AddRule(Rule{Identity: 2, Verdict: Allow}); err != nil {
		t.Fatalf("AddRule(allow): %v", err)
	}

	inject(t, device, echoRequest(t, 3))
	time.Sleep(100 * time.Millisecond)

	stats, err := filter.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats[StatAllow] == 0 {
		t.Errorf("uzunroq prefiks ustunlik qilmadi (tashlangan=%d)", stats[StatDrop])
	}
}

// Aniq port qoidasi umumiy qoidadan ustun bo'lishi kerak.
func TestXDPPolicy_SpecificRuleBeatsWildcard(t *testing.T) {
	requireKernel(t)
	device := testDevice(t)

	filter, err := Load(Config{Interface: device.Name(), Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	const identity = 5
	if err := filter.SetIdentity(netip.MustParsePrefix(peerAddr+"/128"), identity); err != nil {
		t.Fatalf("SetIdentity: %v", err)
	}

	// Umumiy: hammaga ruxsat. Aniqroq: ICMPv6 ga taqiq.
	if err := filter.AddRule(Rule{Identity: identity, Verdict: Allow}); err != nil {
		t.Fatalf("AddRule(any): %v", err)
	}
	if err := filter.AddRule(Rule{Identity: identity, Proto: 58, Verdict: Drop}); err != nil {
		t.Fatalf("AddRule(icmp): %v", err)
	}

	inject(t, device, echoRequest(t, 4))
	time.Sleep(100 * time.Millisecond)

	stats, err := filter.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats[StatDrop] == 0 {
		t.Errorf("aniqroq qoida ustunlik qilmadi (ruxsat=%d)", stats[StatAllow])
	}
}

// Dry-run rejimida paket tashlanmasligi, lekin hisoblanishi kerak.
//
// Deny-by-default siyosatida bu ayniqsa muhim: qoidalar to'liq
// yozilmagan bo'lsa, enforce rejimi butun overlay'ni kesib qo'yardi.
func TestXDPPolicy_DryRunDoesNotDrop(t *testing.T) {
	requireKernel(t)
	device := testDevice(t)

	filter, err := Load(Config{Interface: device.Name(), Enforce: false, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	inject(t, device, echoRequest(t, 5))
	time.Sleep(100 * time.Millisecond)

	stats, err := filter.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}

	// Hukm "tashlash" bo'lgan, lekin paket o'tkazilgan.
	if stats[StatDrop] == 0 {
		t.Error("dry-run hisoblagichi to'ldirilmadi — qoidani sinab bo'lmaydi")
	}
	t.Logf("dry-run: %d paket tashlangan bo'lardi", stats[StatDrop])
}

// Qoidani olib tashlash ishlashi kerak.
func TestXDPPolicy_RuleRemoval(t *testing.T) {
	requireKernel(t)
	device := testDevice(t)

	filter, err := Load(Config{Interface: device.Name(), Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	rule := Rule{Identity: 9, Proto: 58, Verdict: Allow}
	if err := filter.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if _, found, _ := filter.Hits(rule); !found {
		t.Fatal("qoida qo'shilmadi")
	}

	if err := filter.RemoveRule(rule); err != nil {
		t.Fatalf("RemoveRule: %v", err)
	}
	if _, found, _ := filter.Hits(rule); found {
		t.Error("qoida o'chirilmadi")
	}

	// Mavjud bo'lmaganini o'chirish xato emas.
	if err := filter.RemoveRule(rule); err != nil {
		t.Errorf("takroriy o'chirish xato berdi: %v", err)
	}
}

// Ajratishdan keyin filtr ortda qolmasligi kerak.
func TestXDPPolicy_CloseDetaches(t *testing.T) {
	requireKernel(t)
	device := testDevice(t)

	filter, err := Load(Config{Interface: device.Name(), Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if err := filter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := filter.Close(); err != nil {
		t.Errorf("takroriy Close: %v", err)
	}

	// Ajratilgandan keyin paket tegilmasdan o'tishi kerak.
	inject(t, device, echoRequest(t, 6))
}
