// Package tcpolicy overlay interfeysida zero-trust ACL ni qo'llaydi
// (DEV_SPEC §4.1, `tc_ingress`).
//
// # Nega tc, XDP emas
//
// Zero-trust ACL ICHKI overlay manzillari bo'yicha yoziladi: "node A
// node B ning 443-portiga kira oladi". XDP `eth0` da shifrlangan
// tashqi paketni ko'radi va uning ichi unga ko'rinmaydi.
//
// `cc0` ga kirayotgan paket esa allaqachon ochilgan — cc01d uni
// deshifrlab TUN'ga yozgan. Aynan shu nuqtada ichki manzillar
// ko'rinadi.
//
// Hujjatning §4.3 dagi psevdokodi policy'ni XDP ichiga qo'yadi va
// §4.1 dagi jadval tc_ingress ga. Ular zid; to'g'risi tc.
//
// # Kalit sxemasi
//
// §4.2 dagi eskiz src, dst, port va protokolni bitta LPM kalitiga
// birlashtiradi. Bu ishlamaydi: LPM prefiksi kalitning BOSHIDAN
// sanaydi, ya'ni src bitlarini tashlab dst ga o'tib bo'lmaydi va
// "istalgan src, aniq dst" qoidasini ifodalab bo'lmaydi.
//
// Buning o'rniga ikki bosqich: manba prefiksi → identity, keyin
// (identity, port, protokol) → hukm.
package tcpolicy

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/ebpf"
)

//go:embed tc_policy.o
var programELF []byte

// Verdict — qoida hukmi.
type Verdict uint8

const (
	// Drop — paket tashlanadi.
	Drop Verdict = 0

	// Allow — paket o'tkaziladi.
	Allow Verdict = 1
)

func (v Verdict) String() string {
	if v == Allow {
		return "allow"
	}
	return "drop"
}

// IdentityUnknown — manba prefiksi hech qanday qoidaga tushmasa.
//
// Nol "noma'lum manba" degani va unga ham qoida yozish mumkin —
// masalan hamma noma'lum manbaga ICMPv6 ga ruxsat berish.
const IdentityUnknown uint32 = 0

// Policy hisoblagichlarining indekslari.
//
// ⚠️ `bpf/include/cc01_maps.h` dagi `enum cc01_policy_stat` bilan
// AYNAN mos kelishi shart.
const (
	StatTotal = iota
	StatAllow
	StatDrop
	StatDropMalformed
	StatNotIPv6
	StatNoRule
	StatEventLost
	StatCacheHit
	StatCacheMiss
	statMax
)

var statNames = [statMax]string{
	StatTotal:         "jami",
	StatAllow:         "ruxsat berilgan",
	StatDrop:          "tashlangan",
	StatDropMalformed: "buzuq sarlavha",
	StatNotIPv6:       "IPv6 emas",
	StatNoRule:        "qoida topilmadi",
	StatEventLost:     "yo'qolgan hodisalar",
	StatCacheHit:      "keshdan topilgan",
	StatCacheMiss:     "keshda yo'q",
}

// FlagEnforce — hukmni qo'llash. O'chirilgan bo'lsa (dry-run) hamma
// paket o'tkaziladi, lekin hisoblagichlar to'ldiriladi.
//
// Deny-by-default siyosatida bu ayniqsa muhim: qoidalar to'liq
// yozilmagan bo'lsa, enforce rejimi butun trafikni kesib qo'yardi.
const FlagEnforce uint32 = 1 << 0

// ErrNotLayer3 — interfeys L3 emas.
var ErrNotLayer3 = errors.New("tcpolicy: interfeys L3 emas")

// Rule — bitta ruxsat qoidasi.
type Rule struct {
	// Identity — manba guruhi.
	Identity uint32

	// Port — maqsad porti. 0 = istalgan.
	Port uint16

	// Proto — IP protokol raqami (6=TCP, 17=UDP, 58=ICMPv6).
	// 0 = istalgan.
	Proto uint8

	// Verdict — hukm.
	Verdict Verdict

	// RuleID — CP dagi qoida identifikatori (audit uchun).
	RuleID uint32
}

// Config — filtr sozlamalari.
type Config struct {
	// Interface — overlay interfeysi (odatda `cc0`).
	Interface string

	// Enforce — hukmni qo'llash. false bo'lsa dry-run.
	Enforce bool

	// EventSample — har nechta tashlashdan bittasi hodisa
	// sifatida yuboriladi. 0 = hodisalar o'chirilgan.
	//
	// Bo'sh qoldirilsa DefaultEventSample ishlatiladi.
	EventSample uint32

	Logger *slog.Logger
}

// DefaultEventSample — standart namuna olish qadami.
//
// Har bir tashlash uchun hodisa yubormaymiz: deny-by-default
// siyosatida qoidalar to'liq yozilmagan bo'lsa hamma paket
// tashlanadi va hodisalar oqimi kuzatuv vositasini xizmatni
// o'chirish vositasiga aylantirardi.
const DefaultEventSample uint32 = 16

// Filter — yuklangan va biriktirilgan tc dasturi.
type Filter struct {
	collection *ebpf.Collection
	detach     func() error
	iface      string
	config     Config
	log        *slog.Logger

	// generation — qoidalar to'plamining avlodi. Har bir
	// o'zgarishda oshadi va keshlangan hukmlarni eskirtiradi.
	generation atomic.Uint32
}

// Load dasturni yuklaydi va interfeysga biriktiradi.
//
// Interfeys L3 bo'lishi SHART (MAC manzili yo'q). Dastur paketni
// to'g'ridan-to'g'ri IPv6 sarlavhasidan boshlab o'qiydi va Ethernet
// sarlavhali qurilmada u paketni noto'g'ri talqin qilardi.
func Load(cfg Config) (*Filter, error) {
	if cfg.Interface == "" {
		return nil, errors.New("tcpolicy: interfeys berilmagan")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("tcpolicy: interfeys topilmadi (%s): %w", cfg.Interface, err)
	}

	// L2 qurilmada dastur paketni noto'g'ri o'qirdi va bu JIMGINA
	// noto'g'ri hukmlarga olib kelardi — Ethernet sarlavhasining
	// baytlari IPv6 sarlavhasi deb talqin qilinardi.
	layer3, err := isLayer3(cfg.Interface)
	if err != nil {
		return nil, err
	}
	if !layer3 {
		return nil, fmt.Errorf("%w: %s; dastur cc0 kabi TUN qurilmasi uchun",
			ErrNotLayer3, cfg.Interface)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(programELF))
	if err != nil {
		return nil, fmt.Errorf("tcpolicy: dasturni o'qish: %w", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			return nil, fmt.Errorf("tcpolicy: verifier rad etdi:\n%+v", verifier)
		}
		return nil, fmt.Errorf("tcpolicy: yuklash: %w", err)
	}

	program := collection.Programs["cc01_tc_policy"]
	if program == nil {
		collection.Close()
		return nil, errors.New("tcpolicy: cc01_tc_policy dasturi topilmadi")
	}

	filter := &Filter{
		collection: collection,
		iface:      cfg.Interface,
		log:        cfg.Logger.With("component", "tcpolicy"),
	}

	// Sozlama biriktirishdan OLDIN: aks holda dastur ishlay
	// boshlagan, lekin sozlama bo'sh bo'lgan oyna ochilardi.
	if cfg.EventSample == 0 {
		cfg.EventSample = DefaultEventSample
	}
	filter.config = cfg

	if err := filter.Configure(cfg); err != nil {
		collection.Close()
		return nil, err
	}

	detach, err := attachIngress(program, iface.Index)
	if err != nil {
		collection.Close()
		return nil, err
	}
	filter.detach = detach

	filter.log.Info("policy filtri biriktirildi",
		"interface", cfg.Interface, "enforce", cfg.Enforce)

	return filter, nil
}

// Configure sozlamani yangilaydi.
func (f *Filter) Configure(cfg Config) error {
	configMap := f.collection.Maps["cc01_policy_config"]
	if configMap == nil {
		return errors.New("tcpolicy: config map topilmadi")
	}

	var flags uint32
	if cfg.Enforce {
		flags = FlagEnforce
	}

	value := configValue{
		Flags:       flags,
		PolicyGen:   f.generation.Load(),
		EventSample: cfg.EventSample,
	}
	if err := configMap.Put(uint32(0), value); err != nil {
		return fmt.Errorf("tcpolicy: sozlamani yozish: %w", err)
	}

	f.config = cfg
	return nil
}

// invalidate hukm keshini eskirgan deb belgilaydi.
//
// Butun map tozalanmaydi — u O(N) va har bir qoida o'zgarishida uni
// bajarib bo'lmaydi. Buning o'rniga AVLOD raqami oshiriladi va
// yadro eski avloddagi yozuvlarni o'tkazib yuboradi.
//
// ⚠️ Bu HAR QANDAY qoida yoki identity o'zgarishidan keyin
// chaqirilishi SHART. Aks holda keshlangan hukm qoida
// o'chirilgandan keyin ham amal qilib qolardi: taqiqlangan oqim
// ochiq qolardi va buni sezish deyarli imkonsiz bo'lardi.
//
// Shu sababdan u mutatsiya qiluvchi metodlarning ICHIDA chaqiriladi,
// chaqiruvchiga qoldirilmaydi — unutish juda oson bo'lardi.
func (f *Filter) invalidate() error {
	f.generation.Add(1)
	return f.Configure(f.config)
}

// Generation — qoidalar to'plamining joriy avlodi (diagnostika
// uchun).
func (f *Filter) Generation() uint32 { return f.generation.Load() }

// SetEnforce hukmni qo'llashni yoqadi yoki o'chiradi, qolgan
// sozlamalarga tegmasdan.
func (f *Filter) SetEnforce(enforce bool) error {
	cfg := f.config
	cfg.Enforce = enforce
	return f.Configure(cfg)
}

// SetIdentity manba prefiksini guruhga bog'laydi.
//
// Uzunroq prefiks ustunlik qiladi (longest-prefix match): `::/0`
// hammaga, `2a0e:1::5/128` esa aniq bitta nodega tegishli qoida
// beradi.
func (f *Filter) SetIdentity(prefix netip.Prefix, identity uint32) error {
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return fmt.Errorf("tcpolicy: faqat IPv6 prefiks: %v", prefix)
	}

	identities := f.collection.Maps["cc01_identity"]
	if identities == nil {
		return errors.New("tcpolicy: identity map topilmadi")
	}

	key := identityKey{PrefixLen: uint32(prefix.Bits())}
	addr := prefix.Masked().Addr().As16()
	copy(key.Addr[:], addr[:])

	if err := identities.Put(key, identity); err != nil {
		return fmt.Errorf("tcpolicy: identity yozuvi (%v): %w", prefix, err)
	}
	return f.invalidate()
}

// RemoveIdentity prefiks bog'lanishini olib tashlaydi.
func (f *Filter) RemoveIdentity(prefix netip.Prefix) error {
	identities := f.collection.Maps["cc01_identity"]
	if identities == nil {
		return errors.New("tcpolicy: identity map topilmadi")
	}

	key := identityKey{PrefixLen: uint32(prefix.Bits())}
	addr := prefix.Masked().Addr().As16()
	copy(key.Addr[:], addr[:])

	if err := identities.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("tcpolicy: identity yozuvini o'chirish (%v): %w", prefix, err)
	}
	return f.invalidate()
}

// AddRule qoida qo'shadi yoki mavjudini yangilaydi.
func (f *Filter) AddRule(rule Rule) error {
	rules := f.collection.Maps["cc01_policy"]
	if rules == nil {
		return errors.New("tcpolicy: policy map topilmadi")
	}

	key := policyKey{Identity: rule.Identity, DPort: rule.Port, Proto: rule.Proto}
	value := policyValue{Verdict: uint8(rule.Verdict), RuleID: rule.RuleID}

	if err := rules.Put(key, value); err != nil {
		return fmt.Errorf("tcpolicy: qoida yozish: %w", err)
	}
	return f.invalidate()
}

// RemoveRule qoidani olib tashlaydi.
func (f *Filter) RemoveRule(rule Rule) error {
	rules := f.collection.Maps["cc01_policy"]
	if rules == nil {
		return errors.New("tcpolicy: policy map topilmadi")
	}

	key := policyKey{Identity: rule.Identity, DPort: rule.Port, Proto: rule.Proto}
	if err := rules.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("tcpolicy: qoidani o'chirish: %w", err)
	}
	return f.invalidate()
}

// Hits qoida bo'yicha nechta paket o'tganini qaytaradi.
func (f *Filter) Hits(rule Rule) (uint64, bool, error) {
	rules := f.collection.Maps["cc01_policy"]
	if rules == nil {
		return 0, false, errors.New("tcpolicy: policy map topilmadi")
	}

	key := policyKey{Identity: rule.Identity, DPort: rule.Port, Proto: rule.Proto}
	var value policyValue

	if err := rules.Lookup(key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("tcpolicy: qoidani o'qish: %w", err)
	}
	return value.Hits, true, nil
}

// Stats hisoblagichlarni qaytaradi.
func (f *Filter) Stats() (Stats, error) {
	statsMap := f.collection.Maps["cc01_policy_stats"]
	if statsMap == nil {
		return Stats{}, errors.New("tcpolicy: stats map topilmadi")
	}

	var out Stats
	for index := range uint32(statMax) {
		var perCPU []uint64
		if err := statsMap.Lookup(index, &perCPU); err != nil {
			return Stats{}, fmt.Errorf("tcpolicy: hisoblagich %d: %w", index, err)
		}
		for _, value := range perCPU {
			out[index] += value
		}
	}
	return out, nil
}

// Stats — hisoblagichlar to'plami.
type Stats [statMax]uint64

// Name hisoblagichning nomini qaytaradi.
func (Stats) Name(index int) string {
	if index < 0 || index >= statMax {
		return "noma'lum"
	}
	return statNames[index]
}

// Close dasturni ajratadi.
func (f *Filter) Close() error {
	var errs []error

	if f.detach != nil {
		errs = append(errs, f.detach())
		f.detach = nil
	}
	if f.collection != nil {
		f.collection.Close()
		f.collection = nil
	}

	return errors.Join(errs...)
}

// ── Map kalitlari va qiymatlarining Go nusxalari ─────────────────
//
// ⚠️ `bpf/include/cc01_maps.h` dagilar bilan BAYT-BAYT mos kelishi
// shart. Mos kelmasa yadro xato bermaydi — u baytlarni boshqacha
// talqin qiladi va policy jimgina noto'g'ri ishlaydi.

// configValue — `struct cc01_policy_cfg` ning Go nusxasi.
//
// XDP dagi sozlamadan ALOHIDA: ular bir tuzilmani ulashganda, tc
// uchun maydon qo'shish XDP tomonini jimgina buzgan edi.
type configValue struct {
	Flags       uint32
	PolicyGen   uint32
	EventSample uint32
}

type identityKey struct {
	PrefixLen uint32
	Addr      [16]byte
}

type policyKey struct {
	Identity uint32
	DPort    uint16
	Proto    uint8
	_        uint8
}

type policyValue struct {
	Verdict uint8
	_       [3]uint8
	RuleID  uint32
	Hits    uint64
}
