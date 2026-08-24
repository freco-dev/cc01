//go:build linux

package xdp

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

// Bu testlar HAQIQIY yadroga dastur yuklaydi: verifier, map'lar va
// biriktirish — hammasi rostdan bajariladi. Konteynerda ishga
// tushirish:
//
//	make bpf-verify
func requireKernel(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("XDP yuklash uchun root kerak")
	}

	// Eski yadrolarda BPF xotirasi RLIMIT_MEMLOCK bilan cheklanadi
	// va standart chegara (64 KB) hatto kichik dastur uchun ham
	// yetmaydi.
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("memlock chegarasini olib bo'lmadi: %v", err)
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Sinov muhitining nomlari va manzillari.
//
// ⚠️ Manzillar HAQIQIY o'n oltilik bo'lishi shart. Yaroqsiz manzil
// (masalan "fd00:xdp::1" — `xdp` hex emas) `ip` tomonidan rad
// etiladi, test esa jimgina o'tib ketardi va hech narsa
// tekshirmasdi.
const (
	testLink   = "cc01xdp0"
	testPeer   = "cc01xdp0p"
	testNS     = "cc01xdpns"
	localAddr  = "fd00:cc01:ded:1::1"
	remoteAddr = "fd00:cc01:ded:1::2"
	testPrefix = "/64"
)

// testIface XDP sinovlari uchun veth juftligini yaratadi.
//
// Loopback ishlatilmaydi: unga XDP biriktirish mumkin, lekin u
// haqiqiy interfeys emas va xatti-harakati farq qiladi.
func testIface(t *testing.T) string {
	t.Helper()

	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Skipf("ip %v: %v (%s)", args, err, out)
		}
	}

	cleanupNetwork()
	run("link", "add", testLink, "type", "veth", "peer", "name", testPeer)
	run("link", "set", testLink, "up")

	t.Cleanup(cleanupNetwork)
	return testLink
}

// testNetwork ikki uchi ham sozlangan, ping qilinadigan juftlik
// yaratadi: peer alohida netns'da turadi, shunda paketlar rostdan
// interfeysdan o'tadi.
func testNetwork(t *testing.T) string {
	t.Helper()

	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Skipf("ip %v: %v (%s)", args, err, out)
		}
	}

	cleanupNetwork()

	run("netns", "add", testNS)
	run("link", "add", testLink, "type", "veth", "peer", "name", testPeer)
	run("link", "set", testPeer, "netns", testNS)

	run("addr", "add", localAddr+testPrefix, "dev", testLink, "nodad")
	run("link", "set", testLink, "up")

	run("netns", "exec", testNS, "ip", "addr", "add", remoteAddr+testPrefix, "dev", testPeer, "nodad")
	run("netns", "exec", testNS, "ip", "link", "set", testPeer, "up")
	run("netns", "exec", testNS, "ip", "link", "set", "lo", "up")

	t.Cleanup(cleanupNetwork)
	return testLink
}

func cleanupNetwork() {
	_ = exec.Command("ip", "link", "del", testLink).Run()
	_ = exec.Command("ip", "netns", "del", testNS).Run()
}

// pingWorks netns'dan bizga ping yetib boradimi.
func pingWorks(t *testing.T) bool {
	t.Helper()

	err := exec.Command("ip", "netns", "exec", testNS,
		"ping", "-6", "-c", "2", "-W", "1", localAddr).Run()
	return err == nil
}

// Eng muhim tekshiruv: verifier dasturni QABUL QILADIMI.
//
// Verifier rad etsa, dastur umuman yuklanmaydi — va buni faqat
// haqiqiy yadroda bilib olish mumkin.
func TestXDP_LoadsAndAttaches(t *testing.T) {
	requireKernel(t)
	iface := testIface(t)

	filter, err := Load(Config{Interface: iface, Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	if mode := filter.Mode(); mode != ModeNative && mode != ModeGeneric {
		t.Errorf("kutilmagan rejim: %q", mode)
	}
	t.Logf("biriktirildi: %s rejim", filter.Mode())
}

// Ajratish ortida hech narsa qoldirmasligi kerak.
func TestXDP_CloseDetaches(t *testing.T) {
	requireKernel(t)
	iface := testIface(t)

	filter, err := Load(Config{Interface: iface, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := filter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out, err := exec.Command("ip", "link", "show", iface).CombinedOutput()
	if err != nil {
		t.Fatalf("ip link show: %v", err)
	}
	if contains(string(out), "prog/xdp") {
		t.Errorf("XDP dasturi ajratilmagan:\n%s", out)
	}

	// Ikkinchi Close xato bermasligi kerak.
	if err := filter.Close(); err != nil {
		t.Errorf("takroriy Close: %v", err)
	}
}

// Blocklist yozuvi yadroga yetib borishi va qaytib o'qilishi kerak.
func TestXDP_BlocklistRoundTrip(t *testing.T) {
	requireKernel(t)
	iface := testIface(t)

	filter, err := Load(Config{Interface: iface, Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	addr := netip.MustParseAddr("2a0e:dead:beef::1")

	if _, found, err := filter.Hits(addr); err != nil || found {
		t.Fatalf("yozuv oldindan bor: found=%v err=%v", found, err)
	}

	if err := filter.Block(addr, time.Hour); err != nil {
		t.Fatalf("Block: %v", err)
	}

	hits, found, err := filter.Hits(addr)
	if err != nil {
		t.Fatalf("Hits: %v", err)
	}
	if !found {
		t.Fatal("yozuv topilmadi")
	}
	if hits != 0 {
		t.Errorf("yangi yozuvda %d ta urish", hits)
	}

	if err := filter.Unblock(addr); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if _, found, _ := filter.Hits(addr); found {
		t.Error("yozuv o'chirilmadi")
	}
}

// Mavjud bo'lmagan yozuvni o'chirish xato emas — chaqiruvchi
// holatni bilishi shart bo'lmasligi kerak.
func TestXDP_UnblockUnknownIsNoError(t *testing.T) {
	requireKernel(t)
	iface := testIface(t)

	filter, err := Load(Config{Interface: iface, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	if err := filter.Unblock(netip.MustParseAddr("2a0e:1::99")); err != nil {
		t.Errorf("noma'lum yozuvni o'chirish xato berdi: %v", err)
	}
}

// IPv4 manzil rad etilishi kerak: map kaliti 16 bayt va IPv4 uni
// jimgina noto'g'ri to'ldirardi.
func TestXDP_RejectsIPv4(t *testing.T) {
	requireKernel(t)
	iface := testIface(t)

	filter, err := Load(Config{Interface: iface, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	if err := filter.Block(netip.MustParseAddr("192.0.2.1"), 0); err == nil {
		t.Error("IPv4 manzil qabul qilindi")
	}
}

// Rejimni dasturni qayta yuklamasdan almashtirish mumkin bo'lishi
// kerak: qayta yuklash paytida paketlar filtrsiz o'tib ketardi.
func TestXDP_EnforceIsSwitchable(t *testing.T) {
	requireKernel(t)
	iface := testIface(t)

	filter, err := Load(Config{Interface: iface, Enforce: false, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	for _, enforce := range []bool{true, false, true} {
		if err := filter.SetEnforce(enforce); err != nil {
			t.Fatalf("SetEnforce(%v): %v", enforce, err)
		}
	}
}

// Asosiy tekshiruv: filtr HAQIQATAN paket tashlaydimi.
//
// Verifier dasturni qabul qilgani u to'g'ri ishlashini bildirmaydi —
// buni faqat rostdan paket yuborib bilish mumkin.
func TestXDP_DropsBlockedSource(t *testing.T) {
	requireKernel(t)
	iface := testNetwork(t)

	filter, err := Load(Config{Interface: iface, Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	// Avval ping ISHLASHI kerak — aks holda keyingi tekshiruv
	// hech narsani isbotlamaydi.
	if !pingWorks(t) {
		t.Skip("boshlang'ich ping ishlamadi — muhit yaroqsiz")
	}

	remote := netip.MustParseAddr(remoteAddr)
	if err := filter.Block(remote, time.Hour); err != nil {
		t.Fatalf("Block: %v", err)
	}

	if pingWorks(t) {
		t.Fatal("bloklangan manzildan ping O'TIB KETDI")
	}

	hits, found, err := filter.Hits(remote)
	if err != nil || !found {
		t.Fatalf("blocklist yozuvi: found=%v err=%v", found, err)
	}
	if hits == 0 {
		t.Error("paketlar tashlandi, lekin hisoblagich nol")
	}
	t.Logf("tashlangan paketlar: %d", hits)

	// Blokni olib tashlagach ping qayta ishlashi kerak.
	if err := filter.Unblock(remote); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if !pingWorks(t) {
		t.Error("blok olib tashlangandan keyin ham ping ishlamadi")
	}
}

// Dry-run rejimida paket TASHLANMASLIGI, lekin hisoblanishi kerak.
//
// DEV_SPEC §4.4: har qanday yangi qoida avval dry-run'da ishlashi
// shart — ishlab chiqarish tarmog'ida noto'g'ri qoida butun
// trafikni kesib qo'yishi mumkin.
func TestXDP_DryRunCountsButPasses(t *testing.T) {
	requireKernel(t)
	iface := testNetwork(t)

	filter, err := Load(Config{Interface: iface, Enforce: false, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	if !pingWorks(t) {
		t.Skip("boshlang'ich ping ishlamadi — muhit yaroqsiz")
	}

	remote := netip.MustParseAddr(remoteAddr)
	if err := filter.Block(remote, time.Hour); err != nil {
		t.Fatalf("Block: %v", err)
	}

	if !pingWorks(t) {
		t.Fatal("dry-run rejimida paket tashlandi")
	}

	hits, _, err := filter.Hits(remote)
	if err != nil {
		t.Fatalf("Hits: %v", err)
	}
	if hits == 0 {
		t.Error("dry-run hisoblagichi to'ldirilmadi — qoidani sinab bo'lmaydi")
	}
	t.Logf("dry-run: %d paket tashlangan bo'lardi", hits)
}

// Hisoblagichlar haqiqiy trafikda o'sishi kerak.
func TestXDP_CountsTraffic(t *testing.T) {
	requireKernel(t)
	iface := testNetwork(t)

	filter, err := Load(Config{Interface: iface, Enforce: true, Logger: quiet()})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer filter.Close()

	before, err := filter.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}

	if !pingWorks(t) {
		t.Skip("ping ishlamadi — muhit yaroqsiz")
	}

	after, err := filter.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}

	t.Logf("hisoblagichlar: jami=%d o'tkazilgan=%d IPv6-emas=%d buzuq=%d",
		after[StatTotal], after[StatPass], after[StatNotIPv6], after[StatDropMalformed])

	if after[StatTotal] <= before[StatTotal] {
		t.Errorf("trafik o'tdi, lekin hisoblagich o'smadi: %d → %d",
			before[StatTotal], after[StatTotal])
	}
	if after[StatDropMalformed] > 0 {
		t.Errorf("%d ta paket buzuq deb tashlandi — parser xato",
			after[StatDropMalformed])
	}
}

// Noma'lum interfeys aniq xato berishi kerak.
func TestXDP_RejectsUnknownInterface(t *testing.T) {
	requireKernel(t)

	_, err := Load(Config{Interface: "bunday-interfeys-yoq", Logger: quiet()})
	if err == nil {
		t.Fatal("noma'lum interfeys qabul qilindi")
	}
	if errors.Is(err, ErrUnsupported) {
		t.Errorf("xato turi noto'g'ri: %v", err)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
