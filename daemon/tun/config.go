// Package tun overlay uchun TUN qurilmasini yaratadi va sozlaydi.
//
// Qurilmaning o'zi va batch I/O `golang.zx2c4.com/wireguard/tun` dan
// olinadi (DEV_SPEC §1.2). Bu paket ustiga quyidagilarni qo'shadi:
// manzil va marshrut sozlash, ajratilgan routing jadvali, va o'chirishda
// hech nima qolib ketmasligi.
package tun

import (
	"errors"
	"fmt"
	"net/netip"
)

const (
	// DefaultName — interfeys nomi (ARCHITECTURE.md §3.2.1).
	DefaultName = "cc0"

	// DefaultMTU — 1280 bayt: IPv6 minimumi. Shu qiymatda yo'lda
	// fragmentatsiya bo'lmasligi kafolatlanadi, PMTU muammolari yo'q.
	// Hisob-kitob: 1500 - 40 (IPv6) - 8 (UDP) - 16 (cc01) - 16 (tag) = 1420,
	// relay konverti uchun yana 32 bayt; 1280 xavfsiz zaxira bilan tanlangan.
	DefaultMTU = 1280

	// Offset — Read/Write buferlarining boshida BO'SH QOLDIRILISHI shart
	// bo'lgan joy (headroom).
	//
	// Buni platformalar talab qiladi va qiymatlari har xil:
	//   Linux  — virtio-net sarlavhasi uchun 10 bayt (GSO/GRO yoqilganda)
	//   macOS  — protokol oilasi uchun 4 bayt (AF_INET6)
	//   Windows — 0
	//
	// Biz 16 ni tanladik: u hamma talabni qoplaydi VA `noise.HeaderSize`
	// ga teng. Ya'ni datapath paketni shu headroom bilan o'qiydi, keyin
	// kripto qatlami cc01 sarlavhasini AYNAN SHU joyga yozadi — paketni
	// ko'chirish kerak bo'lmaydi.
	//
	// Offset'siz yozish `invalid offset` xatosi beradi; buni oldindan
	// ushlash uchun Read/Write tekshiradi.
	Offset = 16

	// RouteTable — overlay marshrutlari uchun AJRATILGAN jadval
	// (DEV_SPEC §3.3). Asosiy jadvalga tegmaymiz, shunda foydalanuvchining
	// o'z marshrutlari buzilmaydi.
	RouteTable = 51820

	// FirewallMark — cc01d o'zi yuboradigan paketlarga qo'yiladi, shunda
	// ular qayta overlay'ga tushib rekursiya hosil qilmaydi.
	FirewallMark = 0xca01

	// RulePriority — policy routing qoidalarining ustuvorligi.
	RulePriorityLookup   = 5210
	RulePrioritySuppress = 5211
)

var (
	ErrNoAddresses = errors.New("tun: kamida bitta manzil kerak")
	ErrNotIPv6     = errors.New("tun: faqat IPv6 qo'llab-quvvatlanadi")
	ErrBadMTU      = errors.New("tun: MTU 1280..65535 oralig'ida bo'lishi kerak")
	ErrBadName     = errors.New("tun: interfeys nomi yaroqsiz")
)

// Config — TUN qurilmasining kerakli holati.
type Config struct {
	// Name — interfeys nomi. Bo'sh bo'lsa DefaultName ishlatiladi.
	Name string

	// MTU — bo'sh (0) bo'lsa DefaultMTU.
	MTU int

	// Addresses — interfeysga qo'yiladigan manzillar: node GUA /128 va
	// ichki ULA /128.
	Addresses []netip.Prefix

	// Routes — shu interfeysga yo'naltiriladigan prefikslar: tenant /64,
	// relay /32, exit-node rejimida ::/0.
	Routes []netip.Prefix
}

// withDefaults bo'sh maydonlarni to'ldirilgan nusxani qaytaradi.
func (c Config) withDefaults() Config {
	if c.Name == "" {
		c.Name = DefaultName
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	return c
}

// Validate konfiguratsiyani tekshiradi. Qurilma yaratishdan OLDIN
// chaqiriladi: yarim sozlangan interfeys qoldirgandan ko'ra, umuman
// boshlamagan yaxshi.
func (c Config) Validate() error {
	c = c.withDefaults()

	if !validName(c.Name) {
		return fmt.Errorf("%w: %q", ErrBadName, c.Name)
	}

	if c.MTU < DefaultMTU || c.MTU > 65535 {
		return fmt.Errorf("%w: %d", ErrBadMTU, c.MTU)
	}

	if len(c.Addresses) == 0 {
		return ErrNoAddresses
	}

	for _, addr := range c.Addresses {
		if !addr.IsValid() {
			return fmt.Errorf("tun: manzil yaroqsiz: %v", addr)
		}
		// Overlay faqat IPv6 (ADR-003). IPv4 manzil bu yerga tushsa —
		// bu chaqiruvchidagi xato, jimgina o'tkazib yubormaymiz.
		if !addr.Addr().Is6() || addr.Addr().Is4In6() {
			return fmt.Errorf("%w: %v", ErrNotIPv6, addr)
		}
		if addr.Bits() != 128 {
			return fmt.Errorf("tun: manzil /128 bo'lishi kerak: %v", addr)
		}
	}

	for _, route := range c.Routes {
		if !route.IsValid() {
			return fmt.Errorf("tun: marshrut yaroqsiz: %v", route)
		}
		if !route.Addr().Is6() || route.Addr().Is4In6() {
			return fmt.Errorf("%w: %v", ErrNotIPv6, route)
		}
		// Marshrut prefiksining host bitlari nolga tenglashtirilgan
		// bo'lishi kerak, aks holda netlink uni rad etadi.
		if route.Masked() != route {
			return fmt.Errorf("tun: marshrut normallashtirilmagan: %v (kerak %v)",
				route, route.Masked())
		}
	}

	return nil
}

// validName — Linux interfeys nomi cheklovlari: 1..15 belgi, bo'sh joy
// va '/' bo'lmasligi kerak.
func validName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if r == '/' || r == ' ' || r == 0 {
			return false
		}
	}
	return name != "." && name != ".."
}
