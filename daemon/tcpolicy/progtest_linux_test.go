//go:build linux

package tcpolicy

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// `BPF_PROG_TEST_RUN` — dasturni sintetik paket bilan yadroda
// ishlatadi: interfeys ham, tarmoq ham kerak emas (DEV_SPEC §8).
//
// ⚠️ TUZOQ: `SCHED_CLS` uchun yadro test paketini L2 deb hisoblaydi.
// `bpf_prog_test_run_skb` avval `eth_type_trans` chaqiradi (u
// `skb->protocol` ni 12–13-baytlardan o'qiydi va ma'lumot
// ko'rsatkichini 14 baytga suradi), so'ng `is_l2` rost bo'lgani
// uchun `__skb_push(skb, ETH_HLEN)` bilan ORTGA qaytaradi.
//
// Natijada dastur biz bergan buferni 0-baytdan ko'radi. Bizning
// dasturimiz esa TUN (L3) uchun yozilgan va 0-baytda IPv6
// sarlavhasini kutadi — demak paketni Ethernet'siz berishimiz kerak.
//
// Yagona shart: `eth_type_trans` 12–13-baytlarni ethertype deb
// o'qiydi va ular IPv6 sarlavhasida manba manzilining UCHINCHI
// hextet'iga to'g'ri keladi. Shuning uchun test manzillarida u
// `86dd` bo'lishi shart — `l3IPv6` buni tekshiradi.

// TC hukmlari (linux/pkt_cls.h).
const (
	tcActOK   uint32 = 0
	tcActShot uint32 = 2
)

// testSrc va testDst — uchinchi hextet'i `86dd` bo'lgan manzillar,
// yuqoridagi izohga qarang.
var (
	testSrc = netip.MustParseAddr("2a0e:1:86dd::1")
	testDst = netip.MustParseAddr("2a0e:1:86dd::2")
)

func tcVerdictName(v uint32) string {
	switch v {
	case tcActOK:
		return "OK"
	case tcActShot:
		return "SHOT"
	default:
		return "noma'lum"
	}
}

// tcProgram sintetik ishga tushirish uchun dasturni yuklaydi.
func tcProgram(t *testing.T, name string, enforce bool) (*ebpf.Program, *ebpf.Collection) {
	t.Helper()
	requireKernel(t)

	collection, err := loadCollection()
	if err != nil {
		t.Fatalf("loadCollection: %v", err)
	}
	t.Cleanup(collection.Close)

	program := collection.Programs[name]
	if program == nil {
		t.Fatalf("%s topilmadi", name)
	}

	var flags uint32
	if enforce {
		flags = FlagEnforce
	}

	// Sozlama yozilmasa dastur fail-open ishlaydi va hamma test
	// PASS berardi — ya'ni hech narsa tekshirilmasdi.
	if err := collection.Maps["cc01_policy_config"].Put(uint32(0), configValue{
		Flags: flags, EventSample: 1, MSSClamp: DefaultMSSClamp,
	}); err != nil {
		t.Fatalf("sozlama: %v", err)
	}

	return program, collection
}

// l3IPv6 Ethernet'siz IPv6 paketini yasaydi.
func l3IPv6(t *testing.T, src, dst netip.Addr, nextHeader uint8, payload []byte) []byte {
	t.Helper()

	packet := make([]byte, 40+len(payload))
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = nextHeader
	packet[7] = 64
	copy(packet[8:24], src.AsSlice())
	copy(packet[24:40], dst.AsSlice())
	copy(packet[40:], payload)

	// Yuqoridagi izohdagi shart. Manzil o'zgartirilsa test jimgina
	// "IPv6 emas" yo'liga tushib ketardi va hamma narsa PASS berardi.
	if got := binary.BigEndian.Uint16(packet[12:14]); got != 0x86dd {
		t.Fatalf("manba manzilining uchinchi hextet'i %#04x, 0x86dd bo'lishi shart "+
			"(aks holda eth_type_trans paketni IPv6 deb bilmaydi)", got)
	}

	return packet
}

func tcpPayload(sport, dport uint16) []byte {
	payload := make([]byte, 20)
	binary.BigEndian.PutUint16(payload[0:2], sport)
	binary.BigEndian.PutUint16(payload[2:4], dport)
	payload[12] = 5 << 4 // data offset
	return payload
}

func runTC(t *testing.T, program *ebpf.Program, packet []byte) uint32 {
	t.Helper()

	verdict, err := program.Run(&ebpf.RunOptions{Data: packet})
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return verdict
}

// setIdentity manzilni guruhga bog'laydi.
func setIdentity(t *testing.T, collection *ebpf.Collection, addr netip.Addr, identity uint32) {
	t.Helper()

	key := identityKey{PrefixLen: 128}
	raw := addr.As16()
	copy(key.Addr[:], raw[:])

	if err := collection.Maps["cc01_identity"].Put(key, identity); err != nil {
		t.Fatalf("identity: %v", err)
	}
}

// putRule bitta ruxsat qoidasini yozadi.
func putRule(t *testing.T, collection *ebpf.Collection,
	identity uint32, dport uint16, direction Direction) {
	t.Helper()

	if err := collection.Maps["cc01_policy"].Put(
		policyKey{Identity: identity, DPort: dport, Proto: 6, Direction: uint8(direction)},
		policyValue{Verdict: uint8(Allow), RuleID: 1},
	); err != nil {
		t.Fatalf("qoida: %v", err)
	}
}

// allowRule ikkalasini birga bajaradi.
func allowRule(t *testing.T, collection *ebpf.Collection,
	addr netip.Addr, identity uint32, dport uint16, direction Direction) {
	t.Helper()

	setIdentity(t, collection, addr, identity)
	putRule(t, collection, identity, dport, direction)
}

// IPv6 bo'lmagan trafikka tegilmasligi kerak.
func TestProgTest_TCPassesNonIPv6(t *testing.T) {
	program, _ := tcProgram(t, "cc01_tc_ingress", true)

	// 12–13-baytlari IPv4 ethertype: eth_type_trans skb->protocol
	// ni ETH_P_IP qilib qo'yadi.
	packet := make([]byte, 60)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)

	if verdict := runTC(t, program, packet); verdict != tcActOK {
		t.Errorf("%s, OK kutilgan edi", tcVerdictName(verdict))
	}
}

// Kesilgan IPv6 sarlavhasi tashlanishi kerak.
func TestProgTest_TCDropsMalformed(t *testing.T) {
	program, collection := tcProgram(t, "cc01_tc_ingress", true)

	// 40 bayt kerak, 30 bayt beramiz.
	packet := make([]byte, 30)
	packet[0] = 6 << 4
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)

	if verdict := runTC(t, program, packet); verdict != tcActShot {
		t.Errorf("%s, SHOT kutilgan edi", tcVerdictName(verdict))
	}
	if stats := readPolicyStats(t, collection); stats[StatDropMalformed] == 0 {
		t.Error("buzuq paket hisoblagichi to'ldirilmadi")
	}
}

// Qoidasiz paket tashlanishi kerak — deny-by-default.
func TestProgTest_TCDeniesByDefault(t *testing.T) {
	program, collection := tcProgram(t, "cc01_tc_ingress", true)

	packet := l3IPv6(t, testSrc, testDst, 6, tcpPayload(40000, 443))

	if verdict := runTC(t, program, packet); verdict != tcActShot {
		t.Fatalf("%s, SHOT kutilgan edi", tcVerdictName(verdict))
	}
	if stats := readPolicyStats(t, collection); stats[StatNoRule] == 0 {
		t.Error("qoidasiz hisoblagichi to'ldirilmadi")
	}
}

// Mos qoida paketni o'tkazishi kerak.
func TestProgTest_TCAllowsMatchingRule(t *testing.T) {
	program, collection := tcProgram(t, "cc01_tc_ingress", true)
	allowRule(t, collection, testSrc, 7, 443, Ingress)

	packet := l3IPv6(t, testSrc, testDst, 6, tcpPayload(40000, 443))
	if verdict := runTC(t, program, packet); verdict != tcActOK {
		stats := readPolicyStats(t, collection)
		t.Fatalf("%s, OK kutilgan edi (jami=%d ruxsat=%d qoidasiz=%d)",
			tcVerdictName(verdict), stats[StatTotal], stats[StatAllow], stats[StatNoRule])
	}

	// Boshqa port o'sha qoidaga tushmasligi kerak.
	other := l3IPv6(t, testSrc, testDst, 6, tcpPayload(40000, 80))
	if verdict := runTC(t, program, other); verdict != tcActShot {
		t.Errorf("boshqa port: %s, SHOT kutilgan edi", tcVerdictName(verdict))
	}
}

// Kirish qoidasi chiqish trafigiga tegishli bo'lmasligi kerak.
func TestProgTest_TCSeparatesDirections(t *testing.T) {
	ingress, collection := tcProgram(t, "cc01_tc_ingress", true)

	egress := collection.Programs["cc01_tc_egress"]
	if egress == nil {
		t.Fatal("cc01_tc_egress topilmadi")
	}

	// IKKALA manzil ham bir guruhda. Shunday qilmasak, chiqishda
	// identity 0 bo'lib qolardi va test yo'nalishni emas, shunchaki
	// "identity topilmadi" ni tekshirardi.
	setIdentity(t, collection, testSrc, 7)
	setIdentity(t, collection, testDst, 7)

	// Qoida esa FAQAT kirish uchun. Endi kirish va chiqish
	// o'rtasidagi yagona farq — kalitdagi `direction` bayti.
	putRule(t, collection, 7, 443, Ingress)

	packet := l3IPv6(t, testSrc, testDst, 6, tcpPayload(40000, 443))

	if verdict := runTC(t, ingress, packet); verdict != tcActOK {
		t.Errorf("kirish: %s, OK kutilgan edi", tcVerdictName(verdict))
	}
	if verdict := runTC(t, egress, packet); verdict != tcActShot {
		t.Errorf("chiqish: %s, SHOT kutilgan edi — kirish qoidasi "+
			"chiqishga tegishli bo'lib qoldi", tcVerdictName(verdict))
	}
}

// Dry-run rejimida paket tashlanmasligi kerak.
func TestProgTest_TCDryRunPasses(t *testing.T) {
	program, collection := tcProgram(t, "cc01_tc_ingress", false)

	packet := l3IPv6(t, testSrc, testDst, 6, tcpPayload(40000, 443))
	if verdict := runTC(t, program, packet); verdict != tcActOK {
		t.Errorf("dry-run: %s, OK kutilgan edi", tcVerdictName(verdict))
	}

	// Lekin hisoblagich baribir to'ldirilishi kerak — dry-run'ning
	// butun foydasi shunda.
	if stats := readPolicyStats(t, collection); stats[StatDrop] == 0 {
		t.Error("dry-run hisoblagichi to'ldirilmadi")
	}
}

// SYN paketining MSS'i kichraytirilishi kerak.
func TestProgTest_TCClampsMSS(t *testing.T) {
	_, collection := tcProgram(t, "cc01_tc_ingress", true)

	egress := collection.Programs["cc01_tc_egress"]
	if egress == nil {
		t.Fatal("cc01_tc_egress topilmadi")
	}
	allowRule(t, collection, testDst, 7, 443, Egress)

	// SYN + MSS opsiyasi (kind=2, len=4, qiymat=1440).
	payload := make([]byte, 24)
	binary.BigEndian.PutUint16(payload[0:2], 40000)
	binary.BigEndian.PutUint16(payload[2:4], 443)
	payload[12] = 6 << 4 // data offset = 6 (20 + 4 bayt opsiya)
	payload[13] = 0x02   // SYN
	payload[20] = 2      // TCPOPT_MAXSEG
	payload[21] = 4
	binary.BigEndian.PutUint16(payload[22:24], 1440)

	packet := l3IPv6(t, testSrc, testDst, 6, payload)

	out, err := egress.Run(&ebpf.RunOptions{Data: packet, DataOut: make([]byte, len(packet)+64)})
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	if out != tcActOK {
		t.Fatalf("%s, OK kutilgan edi", tcVerdictName(out))
	}

	if stats := readPolicyStats(t, collection); stats[StatMSSClamped] == 0 {
		t.Errorf("MSS kichraytirilmadi (jami=%d)", stats[StatEgressTotal])
	}
}

// Hukm keshi ikkinchi paketdan boshlab ishlashi kerak.
func TestProgTest_TCCachesVerdict(t *testing.T) {
	program, collection := tcProgram(t, "cc01_tc_ingress", true)

	packet := l3IPv6(t, testSrc, testDst, 6, tcpPayload(40000, 443))
	for range 5 {
		runTC(t, program, packet)
	}

	stats := readPolicyStats(t, collection)
	if stats[StatCacheHit] == 0 {
		t.Fatalf("kesh ishlamadi (o'tkazib yuborilgan=%d)", stats[StatCacheMiss])
	}
	if stats[StatCacheHit] <= stats[StatCacheMiss] {
		t.Errorf("kesh samarasiz: %d topildi, %d o'tkazib yuborildi",
			stats[StatCacheHit], stats[StatCacheMiss])
	}
}

// Faza 2 DoD: hodisa quvuri 100k/s ni yo'qotishsiz ko'tarishi kerak.
//
// MUHIM: hodisa PAKETGA emas, OQIMGA chiqadi — `emit_event` faqat
// kesh o'tkazib yuborilgan sekin yo'lda chaqiriladi. Ya'ni bitta
// manbadan kelgan million paket bitta hodisa beradi. Bu ataylab:
// flood paytida jurnal emas, hisoblagich o'sadi.
//
// Shu sababli o'lchov har safar BOSHQA manba portidan paket
// yuboradi — har biri yangi oqim, ya'ni yangi hodisa.
func TestProgTest_EventThroughput(t *testing.T) {
	program, collection := tcProgram(t, "cc01_tc_ingress", true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	filter := &Filter{collection: collection, log: quiet()}
	events, err := filter.Events(ctx)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}

	received := make(chan int, 1)
	go func() {
		var total int
		for range events {
			total++
		}
		received <- total
	}()

	// Manba porti uint16 — 60k dan ortiq turli oqim yasab
	// bo'lmaydi. Takrorlangan port kesh urishiga tushib, o'lchovni
	// jimgina suyultirardi.
	const flows = 60_000

	// Paketlarni oldindan yasaymiz — o'lchovga Go'ning paket
	// yasashi emas, quvurning o'zi tushishi kerak.
	packets := make([][]byte, flows)
	for i := range packets {
		packets[i] = l3IPv6(t, testSrc, testDst, 6,
			tcpPayload(uint16(1024+i), 443))
	}

	start := time.Now()
	for _, packet := range packets {
		if _, err := program.Run(&ebpf.RunOptions{Data: packet}); err != nil {
			t.Fatalf("Run: %v", err)
		}
	}
	elapsed := time.Since(start)

	// Iste'molchiga navbatni bo'shatishga vaqt beramiz.
	time.Sleep(time.Second)
	cancel()
	got := <-received

	stats := readPolicyStats(t, collection)
	generated := stats[StatCacheMiss]
	lost := stats[StatEventLost]
	rate := float64(generated) / elapsed.Seconds()

	t.Logf("%d oqim %v ichida → %.0f hodisa/s", generated,
		elapsed.Round(time.Millisecond), rate)
	t.Logf("qabul qilingan: %d, yadro tomonda yo'qolgan: %d", got, lost)

	// Bu tezlik quvurning YUQORI chegarasi emas: o'lchovni
	// `BPF_PROG_TEST_RUN` ning syscall narxi cheklaydi. Ya'ni
	// aytish mumkin bo'lgani — quvur shu tezlikda yo'qotishsiz
	// ishladi, tiqilinch dasturda emas.

	if generated == 0 {
		t.Fatal("hodisa hosil qilinmadi — o'lchov hech narsani tekshirmadi")
	}
	if lost > 0 {
		t.Errorf("%d hodisa yo'qoldi (ring buffer to'ldi)", lost)
	}

	// Mezon 100k/s. Hosil qilish tezligi shundan past bo'lsa,
	// o'lchov mezonni umuman tekshirmagan bo'ladi — buni jimgina
	// "muvaffaqiyat" deb ko'rsatmaymiz.
	if rate < 100_000 {
		t.Errorf("hosil qilish tezligi %.0f/s — 100k/s mezoni tekshirilmadi", rate)
	}
}

// Yuqoridagi o'lchovda `yo'qolgan=0` faqat hisoblagich haqiqatan
// ishlasa ma'noga ega. Bu test uni ataylab ishga tushiradi:
// iste'molchi umuman yo'q, ya'ni ring buffer to'lishi shart.
func TestProgTest_EventLossIsReported(t *testing.T) {
	program, collection := tcProgram(t, "cc01_tc_ingress", true)

	// Events() chaqirilmaydi — hech kim navbatni bo'shatmaydi.
	for i := range 60_000 {
		packet := l3IPv6(t, testSrc, testDst, 6,
			tcpPayload(uint16(1024+i), 443))
		if _, err := program.Run(&ebpf.RunOptions{Data: packet}); err != nil {
			t.Fatalf("Run: %v", err)
		}
	}

	stats := readPolicyStats(t, collection)
	if stats[StatEventLost] == 0 {
		t.Errorf("ring buffer to'ldi, lekin yo'qotish qayd etilmadi "+
			"(hodisa=%d) — hisoblagich yolg'on tinchlik beradi",
			stats[StatCacheMiss])
	}
	t.Logf("iste'molchisiz %d oqimdan %d hodisa yo'qoldi",
		stats[StatCacheMiss], stats[StatEventLost])
}

func readPolicyStats(t *testing.T, collection *ebpf.Collection) Stats {
	t.Helper()

	var out Stats
	for index := range uint32(statMax) {
		var perCPU []uint64
		if err := collection.Maps["cc01_policy_stats"].Lookup(index, &perCPU); err != nil {
			t.Fatalf("hisoblagich %d: %v", index, err)
		}
		for _, value := range perCPU {
			out[index] += value
		}
	}
	return out
}
