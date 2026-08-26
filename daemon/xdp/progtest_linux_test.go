//go:build linux

package xdp

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// `BPF_PROG_TEST_RUN` — dasturni SINTETIK paket bilan yadroda
// ishlatadi (DEV_SPEC §8, Faza 2).
//
// Nega u kerak, tarmoqli testlar bo'lgani holda:
//
//   - chegaraviy holatlarni (buzuq sarlavha, qisqa paket) haqiqiy
//     tarmoqda hosil qilish qiyin — yadro ularni oldinroq tashlaydi
//   - tez: interfeys, netns va trafik kerak emas
//   - aniq: paketning har bir bayti biz yozganimizday bo'ladi
//
// Tarmoqli testlar baribir kerak — ular biriktirish va haqiqiy
// datapath'ni tekshiradi. Bu ikkisi bir-birini almashtirmaydi.

// xdpProgram sintetik ishga tushirish uchun dasturni yuklaydi.
func xdpProgram(t *testing.T) (*ebpf.Program, *ebpf.Collection) {
	t.Helper()

	return xdpProgramCfg(t, configValue{Flags: FlagEnforce, EventSample: 1})
}

// xdpProgramCfg dasturni berilgan sozlama bilan yuklaydi.
func xdpProgramCfg(t *testing.T, cfg configValue) (*ebpf.Program, *ebpf.Collection) {
	t.Helper()
	requireKernel(t)

	collection, err := loadCollection()
	if err != nil {
		t.Fatalf("loadCollection: %v", err)
	}
	t.Cleanup(collection.Close)

	program := collection.Programs["cc01_xdp_filter"]
	if program == nil {
		t.Fatal("cc01_xdp_filter topilmadi")
	}

	// Sozlama yozilmasa dastur fail-open ishlaydi va hamma test
	// PASS berardi — ya'ni hech narsa tekshirilmasdi.
	if err := collection.Maps["cc01_config_map"].Put(uint32(0), cfg); err != nil {
		t.Fatalf("sozlama: %v", err)
	}

	return program, collection
}

// ethIPv6 Ethernet + IPv6 sarlavhali paket yasaydi.
func ethIPv6(src, dst netip.Addr, nextHeader uint8, payload []byte) []byte {
	packet := make([]byte, 14+40+len(payload))

	// Ethernet: MAC manzillar ahamiyatsiz, faqat tur muhim.
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd) // ETH_P_IPV6

	ip6 := packet[14:]
	ip6[0] = 6 << 4
	binary.BigEndian.PutUint16(ip6[4:6], uint16(len(payload)))
	ip6[6] = nextHeader
	ip6[7] = 64
	copy(ip6[8:24], src.AsSlice())
	copy(ip6[24:40], dst.AsSlice())
	copy(ip6[40:], payload)

	return packet
}

func udpPayload(sport, dport uint16) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint16(payload[0:2], sport)
	binary.BigEndian.PutUint16(payload[2:4], dport)
	binary.BigEndian.PutUint16(payload[4:6], 8)
	return payload
}

// runXDP dasturni bir marta ishga tushiradi va hukmni qaytaradi.
func runXDP(t *testing.T, program *ebpf.Program, packet []byte) uint32 {
	t.Helper()

	verdict, err := program.Run(&ebpf.RunOptions{Data: packet})
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return verdict
}

// XDP hukmlari (linux/bpf.h).
const (
	xdpAborted  uint32 = 0
	xdpDrop     uint32 = 1
	xdpPass     uint32 = 2
	xdpTX       uint32 = 3
	xdpRedirect uint32 = 4
)

func verdictName(v uint32) string {
	switch v {
	case xdpAborted:
		return "ABORTED"
	case xdpDrop:
		return "DROP"
	case xdpPass:
		return "PASS"
	case xdpTX:
		return "TX"
	case xdpRedirect:
		return "REDIRECT"
	default:
		return "noma'lum"
	}
}

// Buzuq sarlavhali paketlar tashlanishi kerak.
//
// Bunday paketlarni haqiqiy tarmoqda hosil qilish qiyin: yadro
// ularni bizga yetib bormasdan tashlaydi.
func TestProgTest_XDPRejectsMalformed(t *testing.T) {
	program, _ := xdpProgram(t)

	// Ethernet bor, lekin IPv6 sarlavhasi to'liq emas (40 bayt
	// kerak).
	truncated := make([]byte, 14+20)
	binary.BigEndian.PutUint16(truncated[12:14], 0x86dd)
	truncated[14] = 6 << 4

	// Ethernet bor, IPv6 umuman yo'q.
	headerOnly := make([]byte, 14)
	binary.BigEndian.PutUint16(headerOnly[12:14], 0x86dd)

	cases := map[string][]byte{
		"IPv6 sarlavhasi yarim": truncated,
		"faqat Ethernet":        headerOnly,
		"bo'sh":                 {},
		"yarim Ethernet":        make([]byte, 10),
	}

	for name, packet := range cases {
		verdict, err := program.Run(&ebpf.RunOptions{Data: packet})
		if err != nil {
			// Yadro paketni qabul qilmadi — dastur uni umuman
			// ko'rmadi. Bu bizning xatomiz emas, lekin uni
			// jimgina o'tkazib yubormaymiz.
			t.Logf("%s (%d bayt): yadro rad etdi: %v", name, len(packet), err)
			continue
		}
		if verdict != xdpDrop {
			t.Errorf("%s: %s, DROP kutilgan edi", name, verdictName(verdict))
		}
	}
}

// IPv6 bo'lmagan trafikka TEGILMASLIGI kerak: interfeysda boshqa
// xizmatlar ham ishlashi mumkin.
func TestProgTest_XDPPassesNonIPv6(t *testing.T) {
	program, collection := xdpProgram(t)

	packet := make([]byte, 60)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800) // IPv4

	if verdict := runXDP(t, program, packet); verdict != xdpPass {
		t.Errorf("%s, PASS kutilgan edi", verdictName(verdict))
	}

	stats := readStats(t, collection)
	if stats[StatNotIPv6] == 0 {
		t.Error("IPv6-emas hisoblagichi to'ldirilmadi")
	}
}

// Blocklist'dagi manba tashlanishi kerak.
func TestProgTest_XDPDropsBlocklisted(t *testing.T) {
	program, collection := xdpProgram(t)

	src := netip.MustParseAddr("2a0e:dead::1")
	dst := netip.MustParseAddr("2a0e:1::1")
	packet := ethIPv6(src, dst, 59, nil)

	// Avval o'tishi kerak.
	if verdict := runXDP(t, program, packet); verdict != xdpPass {
		t.Fatalf("bloklanmagan manba %s oldi", verdictName(verdict))
	}

	key := src.As16()
	if err := collection.Maps["cc01_blocklist"].Put(key[:], blockValue{}); err != nil {
		t.Fatalf("blocklist: %v", err)
	}

	if verdict := runXDP(t, program, packet); verdict != xdpDrop {
		t.Errorf("bloklangan manba %s oldi, DROP kutilgan edi", verdictName(verdict))
	}
}

// Overlay portiga kelgan paket yo'naltirish yo'liga tushishi kerak.
//
// AF_XDP soketi yo'q, ya'ni fallback PASS qaytadi — bu yo'lni
// yoqish xavfsiz ekanini shu tasdiqlaydi.
func TestProgTest_XDPRedirectsOverlayPort(t *testing.T) {
	program, collection := xdpProgram(t)

	const overlayPort = 51820
	if err := collection.Maps["cc01_config_map"].Put(uint32(0), configValue{
		Flags:       FlagEnforce,
		OverlayPort: overlayPort,
	}); err != nil {
		t.Fatalf("sozlama: %v", err)
	}

	packet := ethIPv6(
		netip.MustParseAddr("2a0e:1::1"),
		netip.MustParseAddr("2a0e:1::2"),
		17, udpPayload(40000, overlayPort))

	verdict := runXDP(t, program, packet)
	if verdict != xdpPass && verdict != xdpRedirect {
		t.Errorf("%s, PASS yoki REDIRECT kutilgan edi", verdictName(verdict))
	}

	if stats := readStats(t, collection); stats[StatRedirect] == 0 {
		t.Error("yo'naltirish hisoblagichi to'ldirilmadi")
	}
}

// XDP_ABORTED hech qachon qaytmasligi kerak: u faqat bug
// holatida chiqadi va CI da nol bo'lishi shart (DEV_SPEC §4.4).
func TestProgTest_XDPNeverAborts(t *testing.T) {
	program, _ := xdpProgram(t)

	packets := [][]byte{
		make([]byte, 14),
		make([]byte, 54),
		ethIPv6(netip.MustParseAddr("2a0e:1::1"), netip.MustParseAddr("2a0e:1::2"), 59, nil),
		ethIPv6(netip.MustParseAddr("2a0e:1::1"), netip.MustParseAddr("2a0e:1::2"), 17, udpPayload(53, 9)),
		ethIPv6(netip.MustParseAddr("2a0e:1::1"), netip.MustParseAddr("2a0e:1::2"), 6, make([]byte, 4)),
	}

	for i, packet := range packets {
		if verdict := runXDP(t, program, packet); verdict == xdpAborted {
			t.Errorf("paket %d ABORTED berdi — bu bug belgisi", i)
		}
	}
}

// readStats hisoblagichlarni to'g'ridan-to'g'ri map'dan o'qiydi.
// Stage 2: token chelagi to'lgach paketlar tashlanishi kerak.
func TestProgTest_XDPRateLimits(t *testing.T) {
	const burst = 20

	program, collection := xdpProgramCfg(t, configValue{
		Flags:       FlagEnforce,
		RatePPS:     burst,
		Burst:       burst,
		EventSample: 1,
	})

	packet := ethIPv6(
		netip.MustParseAddr("2a0e:9::1"),
		netip.MustParseAddr("2a0e:9::2"),
		17, udpPayload(40000, 9999))

	// Chelakdagidan ancha ko'p yuboramiz. `BPF_PROG_TEST_RUN`
	// paketlarni bir zumda o'tkazadi, ya'ni token to'ldirishga
	// vaqt qolmaydi.
	const sent = burst * 10
	var passed int
	for range sent {
		if runXDP(t, program, packet) == xdpPass {
			passed++
		}
	}

	stats := readStats(t, collection)
	t.Logf("%d dan %d o'tdi, %d tashlandi", sent, passed, stats[StatDropRateLimit])

	if stats[StatDropRateLimit] == 0 {
		t.Fatal("chegara ishlamadi — hamma paket o'tdi")
	}
	if passed == 0 {
		t.Error("hech narsa o'tmadi — chelak umuman ishlamayapti")
	}
	// Chelak sig'imi `burst`, demak o'tganlar shundan oshmasligi
	// kerak (bir oz zaxira: test davomida ozgina token tiklanadi).
	if passed > burst*2 {
		t.Errorf("%d paket o'tdi, chelak sig'imi %d", passed, burst)
	}
}

// Stage 2: chegarani muttasil buzgan manba avtomatik bloklanishi kerak.
func TestProgTest_XDPAutoBlocks(t *testing.T) {
	program, collection := xdpProgramCfg(t, configValue{
		Flags:          FlagEnforce,
		RatePPS:        10,
		Burst:          10,
		AutoBlockAfter: 5,
		AutoBlockNS:    uint64(time.Minute),
		EventSample:    1,
	})

	packet := ethIPv6(
		netip.MustParseAddr("2a0e:a::1"),
		netip.MustParseAddr("2a0e:a::2"),
		17, udpPayload(40000, 9999))

	for range 200 {
		runXDP(t, program, packet)
	}

	stats := readStats(t, collection)
	if stats[StatAutoBlocked] == 0 {
		t.Fatalf("avtomatik blok ishlamadi (chegaradan oshgan: %d)",
			stats[StatDropRateLimit])
	}

	// Blok ro'yxatiga haqiqatan tushganini tekshiramiz — aks holda
	// hisoblagich o'sadi-yu, keyingi paketlar baribir sekin yo'ldan
	// o'tardi.
	if stats[StatDropBlocklist] == 0 {
		t.Error("avtomatik bloklandi, lekin blocklist bosqichi ishlamadi")
	}
}

// Stage 3: amplifikatsiya MANBA portlari faqat bayroq yoqilganda
// tashlanadi.
func TestProgTest_XDPDropsAmplification(t *testing.T) {
	// DNS javobi kabi ko'rinadi: manba porti 53.
	dns := ethIPv6(
		netip.MustParseAddr("2a0e:b::1"),
		netip.MustParseAddr("2a0e:b::2"),
		17, udpPayload(53, 40000))

	t.Run("bayroq o'chiq", func(t *testing.T) {
		program, collection := xdpProgramCfg(t, configValue{
			Flags: FlagEnforce, EventSample: 1,
		})
		if verdict := runXDP(t, program, dns); verdict != xdpPass {
			t.Errorf("%s, PASS kutilgan edi", verdictName(verdict))
		}
		if stats := readStats(t, collection); stats[StatDropAmplify] != 0 {
			t.Error("bayroq o'chiq, lekin filtr ishladi")
		}
	})

	t.Run("bayroq yoniq", func(t *testing.T) {
		program, collection := xdpProgramCfg(t, configValue{
			Flags: FlagEnforce | FlagDropAmplify, EventSample: 1,
		})
		if verdict := runXDP(t, program, dns); verdict != xdpDrop {
			t.Errorf("%s, DROP kutilgan edi", verdictName(verdict))
		}
		if stats := readStats(t, collection); stats[StatDropAmplify] == 0 {
			t.Error("amplifikatsiya hisoblagichi to'ldirilmadi")
		}

		// Oddiy manba porti tegishsiz qolishi kerak.
		normal := ethIPv6(
			netip.MustParseAddr("2a0e:b::1"),
			netip.MustParseAddr("2a0e:b::2"),
			17, udpPayload(40000, 9999))
		if verdict := runXDP(t, program, normal); verdict != xdpPass {
			t.Errorf("oddiy port: %s, PASS kutilgan edi", verdictName(verdict))
		}
	})
}

func readStats(t *testing.T, collection *ebpf.Collection) Stats {
	t.Helper()

	var out Stats
	for index := range uint32(statMax) {
		var perCPU []uint64
		if err := collection.Maps["cc01_stats"].Lookup(index, &perCPU); err != nil {
			t.Fatalf("hisoblagich %d: %v", index, err)
		}
		for _, value := range perCPU {
			out[index] += value
		}
	}
	return out
}
