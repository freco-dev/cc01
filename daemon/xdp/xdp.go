// Package xdp cc01 ning XDP filtrini yuklaydi va boshqaradi
// (DEV_SPEC §4).
//
// # Nima uchun XDP
//
// XDP paketni yadro tarmoq stekiga KIRISHIDAN oldin ko'radi — hatto
// `sk_buff` yaratilmaydi. Hujum paytida tashlanadigan paket uchun bu
// eng arzon nuqta.
//
// # Nima bu paketda YO'Q
//
// Hozircha faqat blocklist bosqichi qurilgan. Rate limit, conntrack
// va policy trie (§4.2, §4.3) keyingi qadamlarda qo'shiladi. Skelet
// — yuklash, biriktirish, map boshqaruvi va konteynerda sinash —
// shular uchun ham asos.
package xdp

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Dastur BINARY ko'rinishida ichkariga joylashtiriladi.
//
// Sabab: demonni qurish uchun clang kerak bo'lmasligi kerak, va
// ishga tushirish paytida tashqi fayl qidirish yana bir nosozlik
// manbai bo'lardi. Fayl `make bpf` bilan yangilanadi.
//
//go:embed xdp_filter.o
var programELF []byte

// Statistika hisoblagichlarining indekslari.
//
// ⚠️ Bu qiymatlar `bpf/include/cc01_maps.h` dagi `enum cc01_stat`
// bilan AYNAN mos kelishi shart. Mos kelmasa yadro xato bermaydi —
// biz shunchaki boshqa hisoblagichni o'qiymiz.
const (
	StatTotal = iota
	StatPass
	StatDropBlocklist
	StatDropMalformed
	StatNotIPv6
	StatDropRateLimit
	StatAutoBlocked
	StatRateLimitMapFull
	StatDropAmplify
	StatRedirect
	StatEventLost
	statMax
)

// statNames — chiqarish uchun nomlar.
var statNames = [statMax]string{
	StatTotal:            "jami",
	StatPass:             "o'tkazilgan",
	StatDropBlocklist:    "blocklist bo'yicha tashlangan",
	StatDropMalformed:    "buzuq sarlavha",
	StatNotIPv6:          "IPv6 emas",
	StatDropRateLimit:    "tezlik chegarasidan oshgan",
	StatAutoBlocked:      "avtomatik bloklangan",
	StatRateLimitMapFull: "chelaklar map'i to'lgan",
	StatDropAmplify:      "amplifikatsiya portidan",
	StatRedirect:         "AF_XDP ga yo'naltirilgan",
	StatEventLost:        "yo'qolgan hodisalar",
}

// FlagEnforce — hukmni qo'llash. O'chirilgan bo'lsa (dry-run) hamma
// paket o'tkaziladi, lekin hisoblagichlar to'ldiriladi.
const FlagEnforce uint32 = 1 << 0

// FlagDropAmplify — DNS/NTP/SSDP/memcached MANBA portlaridan kelgan
// UDP paketlarini tashlash.
//
// ⚠️ Standart holatda O'CHIRILGAN. Bu portlardan kelgan paket odatiy
// node uchun HAQIQIY javob bo'lishi mumkin — masalan DNS javobi.
// Uni tashlash node'ning nom yechishini butunlay buzardi.
//
// Bayroq faqat edge/PoP mashinalari uchun: ular hech qachon DNS
// so'ramaydi va bu portlardan kelgan har qanday paket soxta manzil
// bilan kuchaytirilgan hujum belgisidir.
const FlagDropAmplify uint32 = 1 << 1

// Mode — XDP qaysi rejimda biriktirilgan.
type Mode string

const (
	// ModeNative — drayver darajasida. Eng tez yo'l.
	ModeNative Mode = "native"

	// ModeGeneric — yadro stekida, sk_buff yaratilgandan keyin.
	// Sekinroq, lekin har qanday drayverda ishlaydi.
	ModeGeneric Mode = "generic"
)

// ErrUnsupported — yadro yoki muhit XDP ni qo'llab-quvvatlamaydi.
var ErrUnsupported = errors.New("xdp: qo'llab-quvvatlanmaydi")

// Filter — yuklangan va biriktirilgan XDP dasturi.
type Filter struct {
	collection *ebpf.Collection
	attachment link.Link
	mode       Mode
	iface      string
	config     Config
	log        *slog.Logger
}

// Config — filtr sozlamalari.
type Config struct {
	// Interface — qaysi interfeysga biriktiriladi.
	Interface string

	// Enforce — hukmni qo'llash. false bo'lsa dry-run.
	Enforce bool

	// RatePPS — bitta manba /64 uchun soniyasiga ruxsat etilgan
	// paketlar. 0 bo'lsa tezlik cheklanmaydi.
	RatePPS uint32

	// Burst — chelakning sig'imi. 0 bo'lsa RatePPS ishlatiladi
	// (bir soniyalik zaxira).
	Burst uint32

	// AutoBlockAfter — nechta tashlangandan keyin manba
	// blocklist'ga qo'shiladi. 0 = qo'shilmaydi.
	AutoBlockAfter uint32

	// AutoBlockFor — avtomatik blok qancha davom etadi.
	AutoBlockFor time.Duration

	// DropAmplification — amplifikatsiya manba portlaridan kelgan
	// UDP paketlarini tashlash. FlagDropAmplify izohiga qarang.
	DropAmplification bool

	// EventSample — har nechta tashlashdan bittasi hodisa
	// sifatida yuboriladi. 0 = o'chirilgan.
	//
	// Bo'sh qoldirilsa DefaultEventSample.
	EventSample uint32

	// OverlayPort — cc01 datapath'ining UDP porti. Shu portga
	// kelgan paketlar AF_XDP soketiga yo'naltiriladi.
	//
	// AF_XDP soketi ulanmagan bo'lsa paket odatdagi yadro steki
	// orqali ketadi — ya'ni buni yoqish xavfsiz.
	OverlayPort uint16

	Logger *slog.Logger
}

// DefaultEventSample — standart namuna olish qadami.
//
// Hujum paytida har bir tashlash uchun hodisa yuborish ring
// bufferni to'ldirib, kuzatuv vositasini xizmatni o'chirish
// vositasiga aylantirardi.
const DefaultEventSample uint32 = 16

// loadCollection dasturni yadroga yuklaydi, BIRIKTIRMASDAN.
//
// Ajratilgani testlar uchun: `BPF_PROG_TEST_RUN` sintetik paket
// bilan ishlaydi va unga interfeys ham, tarmoq ham kerak emas.
func loadCollection() (*ebpf.Collection, error) {
	if err := removeMemlock(); err != nil {
		return nil, fmt.Errorf("xdp: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(newReader(programELF))
	if err != nil {
		return nil, fmt.Errorf("xdp: dasturni o'qish: %w", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		// Verifier xatosi juda uzun bo'ladi va uni qisqartirish
		// sababni yashirardi — to'liq chiqaramiz.
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			return nil, fmt.Errorf("xdp: verifier rad etdi:\n%+v", verifier)
		}
		return nil, fmt.Errorf("xdp: yuklash: %w", err)
	}

	return collection, nil
}

// Load dasturni yuklaydi va interfeysga biriktiradi.
//
// Biriktirish AVVAL native rejimda urinadi; drayver qo'llamasa
// generic rejimga tushadi va bu haqda ogohlantiradi. Generic rejim
// sekinroq, lekin ishlamaganidan yaxshi — va operator buni logdan
// ko'rishi kerak.
func Load(cfg Config) (*Filter, error) {
	if cfg.Interface == "" {
		return nil, errors.New("xdp: interfeys berilmagan")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("xdp: interfeys topilmadi (%s): %w", cfg.Interface, err)
	}

	collection, err := loadCollection()
	if err != nil {
		return nil, err
	}

	program := collection.Programs["cc01_xdp_filter"]
	if program == nil {
		collection.Close()
		return nil, errors.New("xdp: cc01_xdp_filter dasturi topilmadi")
	}

	filter := &Filter{
		collection: collection,
		iface:      cfg.Interface,
		log:        cfg.Logger.With("component", "xdp"),
	}

	// Konfiguratsiya biriktirishdan OLDIN yoziladi.
	//
	// Aks holda dastur ishlay boshlagan, lekin config map bo'sh
	// bo'lgan oyna ochilardi. U fail-open — ya'ni bir necha
	// millisekund davomida filtr umuman ishlamasdi.
	if err := filter.Configure(cfg); err != nil {
		collection.Close()
		return nil, err
	}

	attachment, mode, err := attach(program, iface.Index)
	if err != nil {
		collection.Close()
		return nil, err
	}

	filter.attachment = attachment
	filter.mode = mode

	filter.log.Info("XDP filtri biriktirildi",
		"interface", cfg.Interface, "mode", mode, "enforce", cfg.Enforce)

	if mode == ModeGeneric {
		filter.log.Warn("XDP generic rejimda — drayver native rejimni qo'llamaydi; "+
			"unumdorlik sezilarli pastroq", "interface", cfg.Interface)
	}

	return filter, nil
}

// attach dasturni biriktiradi: avval native, keyin generic.
func attach(program *ebpf.Program, index int) (link.Link, Mode, error) {
	attachment, err := link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: index,
		Flags:     link.XDPDriverMode,
	})
	if err == nil {
		return attachment, ModeNative, nil
	}

	nativeErr := err

	attachment, err = link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: index,
		Flags:     link.XDPGenericMode,
	})
	if err == nil {
		return attachment, ModeGeneric, nil
	}

	// Ikkala rejim ham ishlamadi — ikkala sababni ham ko'rsatamiz.
	// Faqat oxirgisini ko'rsatish operatorni chalg'itardi.
	return nil, "", fmt.Errorf("%w: native: %v; generic: %v",
		ErrUnsupported, nativeErr, err)
}

// Mode — dastur qaysi rejimda ishlayapti.
func (f *Filter) Mode() Mode { return f.mode }

// Configure butun sozlamani yangilaydi.
//
// Dasturni qayta yuklash KERAK EMAS: sozlama map orqali beriladi.
// Qayta yuklash paytida paketlar filtrsiz o'tib ketardi.
func (f *Filter) Configure(cfg Config) error {
	configMap := f.collection.Maps["cc01_config_map"]
	if configMap == nil {
		return errors.New("xdp: config map topilmadi")
	}

	var flags uint32
	if cfg.Enforce {
		flags = FlagEnforce
	}

	// Burst berilmagan bo'lsa bir soniyalik zaxira: qisqa
	// portlashlar cheklovga tushmasin, aks holda oddiy TCP oynasi
	// ham kesilardi.
	if cfg.DropAmplification {
		flags |= FlagDropAmplify
	}

	burst := cfg.Burst
	if burst == 0 {
		burst = cfg.RatePPS
	}

	sample := cfg.EventSample
	if sample == 0 {
		sample = DefaultEventSample
	}

	value := configValue{
		Flags:          flags,
		RatePPS:        cfg.RatePPS,
		Burst:          burst,
		AutoBlockAfter: cfg.AutoBlockAfter,
		AutoBlockNS:    uint64(cfg.AutoBlockFor.Nanoseconds()),
		EventSample:    sample,
		OverlayPort:    cfg.OverlayPort,
	}

	if err := configMap.Put(uint32(0), value); err != nil {
		return fmt.Errorf("xdp: konfiguratsiyani yozish: %w", err)
	}

	f.config = cfg
	return nil
}

// SetEnforce hukmni qo'llashni yoqadi yoki o'chiradi, qolgan
// sozlamalarga tegmasdan.
func (f *Filter) SetEnforce(enforce bool) error {
	cfg := f.config
	cfg.Enforce = enforce
	return f.Configure(cfg)
}

// Block manzilni blocklist'ga qo'shadi.
//
// `ttl` 0 bo'lsa yozuv muddatsiz. Muddat YADRO vaqti shkalasida
// hisoblanadi (bpf_ktime_get_ns): XDP ichida devor soatini o'qish
// qimmat va u sakrashi mumkin.
func (f *Filter) Block(addr netip.Addr, ttl time.Duration) error {
	if !addr.Is6() || addr.Is4In6() {
		return fmt.Errorf("xdp: faqat IPv6 manzil: %v", addr)
	}

	blocklist := f.collection.Maps["cc01_blocklist"]
	if blocklist == nil {
		return errors.New("xdp: blocklist map topilmadi")
	}

	var expires uint64
	if ttl > 0 {
		now, err := kernelTime()
		if err != nil {
			return err
		}
		expires = now + uint64(ttl.Nanoseconds())
	}

	key := addr.As16()
	value := blockValue{ExpiresNS: expires}

	if err := blocklist.Put(key[:], value); err != nil {
		return fmt.Errorf("xdp: blocklist yozuvi (%v): %w", addr, err)
	}
	return nil
}

// Unblock manzilni blocklist'dan olib tashlaydi.
func (f *Filter) Unblock(addr netip.Addr) error {
	blocklist := f.collection.Maps["cc01_blocklist"]
	if blocklist == nil {
		return errors.New("xdp: blocklist map topilmadi")
	}

	key := addr.As16()
	if err := blocklist.Delete(key[:]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("xdp: blocklist yozuvini o'chirish (%v): %w", addr, err)
	}
	return nil
}

// Hits manzil bo'yicha nechta paket tashlanganini qaytaradi.
func (f *Filter) Hits(addr netip.Addr) (uint64, bool, error) {
	blocklist := f.collection.Maps["cc01_blocklist"]
	if blocklist == nil {
		return 0, false, errors.New("xdp: blocklist map topilmadi")
	}

	key := addr.As16()
	var value blockValue

	if err := blocklist.Lookup(key[:], &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("xdp: blocklist o'qish: %w", err)
	}
	return value.Hits, true, nil
}

// Stats hisoblagichlarni qaytaradi.
//
// Map per-CPU: har bir yadro o'z nusxasiga yozadi va biz hammasini
// qo'shamiz. Shu tufayli tez yo'lda atomik amal kerak emas.
func (f *Filter) Stats() (Stats, error) {
	statsMap := f.collection.Maps["cc01_stats"]
	if statsMap == nil {
		return Stats{}, errors.New("xdp: stats map topilmadi")
	}

	var out Stats

	for index := range uint32(statMax) {
		var perCPU []uint64
		if err := statsMap.Lookup(index, &perCPU); err != nil {
			return Stats{}, fmt.Errorf("xdp: hisoblagich %d: %w", index, err)
		}

		var total uint64
		for _, value := range perCPU {
			total += value
		}
		out[index] = total
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

// Close dasturni ajratadi va resurslarni bo'shatadi.
func (f *Filter) Close() error {
	var errs []error

	if f.attachment != nil {
		errs = append(errs, f.attachment.Close())
	}
	if f.collection != nil {
		f.collection.Close()
	}

	return errors.Join(errs...)
}

// ── Map qiymatlarining Go nusxalari ──────────────────────────────
//
// ⚠️ Bu tuzilmalar `bpf/include/cc01_maps.h` dagilar bilan BAYT-BAYT
// mos kelishi shart. Mos kelmasa yadro xato BERMAYDI — u baytlarni
// boshqacha talqin qiladi va filtr jimgina noto'g'ri ishlaydi.
// O'lchamlar test bilan qulflangan.

type configValue struct {
	Flags          uint32
	RatePPS        uint32
	Burst          uint32
	AutoBlockAfter uint32
	AutoBlockNS    uint64
	EventSample    uint32
	OverlayPort    uint16
	_              uint16
}

type blockValue struct {
	ExpiresNS uint64
	Hits      uint64
}

// RateLimited manba /64 bo'yicha nechta paket tashlanganini
// qaytaradi.
func (f *Filter) RateLimited(addr netip.Addr) (uint64, bool, error) {
	buckets := f.collection.Maps["cc01_ratelimit"]
	if buckets == nil {
		return 0, false, errors.New("xdp: ratelimit map topilmadi")
	}

	full := addr.As16()
	var key [8]byte
	copy(key[:], full[:8])

	var value rateLimitValue

	// BPF_F_LOCK: qiymat ichida spin lock bor va uni qulfsiz
	// o'qish yarim yangilangan holatni ko'rsatishi mumkin.
	if err := buckets.LookupWithFlags(key[:], &value, ebpf.LookupLock); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("xdp: chelakni o'qish: %w", err)
	}

	return value.Dropped, true, nil
}

// rateLimitValue — `struct cc01_rl_value` ning Go nusxasi.
//
// Birinchi maydon — yadro spin lock'i. Go tomonida u shunchaki
// to'ldirish; unga tegilmaydi, lekin joyi bo'lishi shart.
type rateLimitValue struct {
	Lock        uint32
	_           uint32
	TokensMilli uint64
	LastNS      uint64
	Dropped     uint64
}

// SweepInterval — eskirgan chelaklarni tozalash davri.
const SweepInterval = 30 * time.Second

// bucketIdleTimeout — chelak qancha vaqt tegilmasa eskirgan
// hisoblanadi.
//
// Cheklov oynasidan sezilarli uzoq: aks holda faol manbaning
// chelagi tozalanib, u to'la chelak bilan qaytardi va cheklov
// ma'nosini yo'qotardi.
const bucketIdleTimeout = 5 * time.Minute

// Sweep eskirgan chelaklarni o'chiradi va nechtasi olib
// tashlanganini qaytaradi.
//
// Nega userspace tozalaydi: chelaklar map'i oddiy HASH, chunki yadro
// `bpf_spin_lock` ni LRU_HASH'da qabul qilmaydi. Ya'ni avtomatik
// evikatsiya yo'q — tozalanmasa map to'lib qoladi va yangi manbalar
// cheklovsiz o'tib ketardi.
func (f *Filter) Sweep() (int, error) { return f.sweep(bucketIdleTimeout) }

// sweep — testlar muddatni boshqara olishi uchun ajratilgan.
func (f *Filter) sweep(idleFor time.Duration) (int, error) {
	buckets := f.collection.Maps["cc01_ratelimit"]
	if buckets == nil {
		return 0, errors.New("xdp: ratelimit map topilmadi")
	}

	now, err := kernelTime()
	if err != nil {
		return 0, err
	}
	cutoff := now - uint64(idleFor.Nanoseconds())

	var (
		key     [8]byte
		value   rateLimitValue
		stale   [][8]byte
		removed int
	)

	// Avval yig'amiz, keyin o'chiramiz: iteratsiya davomida
	// o'chirish yadro kursorini buzishi mumkin va ba'zi yozuvlar
	// tashlab ketilardi.
	iter := buckets.Iterate()
	for iter.Next(&key, &value) {
		if value.LastNS < cutoff {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("xdp: chelaklarni ko'rib chiqish: %w", err)
	}

	for _, item := range stale {
		if err := buckets.Delete(item[:]); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue // boshqa tomon allaqachon o'chirgan
			}
			return removed, fmt.Errorf("xdp: chelakni o'chirish: %w", err)
		}
		removed++
	}

	return removed, nil
}

// RunSweeper eskirgan chelaklarni davriy tozalab turadi.
//
// ctx bekor qilinganda qaytadi.
func (f *Filter) RunSweeper(ctx context.Context) {
	ticker := time.NewTicker(SweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			removed, err := f.Sweep()
			if err != nil {
				f.log.Warn("chelaklarni tozalash", "err", err)
				continue
			}
			if removed > 0 {
				f.log.Debug("eskirgan chelaklar tozalandi", "count", removed)
			}
		}
	}
}

// removeMemlock BPF xotira chegarasini olib tashlaydi.
//
// Eski yadrolarda BPF map'lari `RLIMIT_MEMLOCK` hisobiga tushadi va
// standart chegara (odatda 64 KB) hatto kichik map uchun ham
// yetmaydi. Yangi yadrolarda hisob memcg'ga ko'chgan, lekin
// konteynerda chegara baribir past bo'lishi mumkin.
//
// Bir marta bajariladi: chegarani har yuklashda o'zgartirish
// keraksiz syscall.
var removeMemlock = sync.OnceValue(func() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("BPF xotira chegarasi: %w", err)
	}
	return nil
})
