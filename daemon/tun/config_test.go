package tun

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func prefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("prefiks parse: %v", err)
	}
	return p
}

func validConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Addresses: []netip.Prefix{prefix(t, "2a0e:1234:1::b7f2/128")},
		Routes:    []netip.Prefix{prefix(t, "2a0e:1234:1::/64")},
	}
}

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{Addresses: []netip.Prefix{prefix(t, "fd01:cc01::1/128")}}.withDefaults()

	if cfg.Name != DefaultName {
		t.Errorf("nom: %q kutilgan, %q olindi", DefaultName, cfg.Name)
	}
	if cfg.MTU != DefaultMTU {
		t.Errorf("MTU: %d kutilgan, %d olindi", DefaultMTU, cfg.MTU)
	}
}

func TestConfig_ValidAccepted(t *testing.T) {
	if err := validConfig(t).Validate(); err != nil {
		t.Fatalf("to'g'ri konfiguratsiya rad etildi: %v", err)
	}
}

func TestConfig_RequiresAddress(t *testing.T) {
	if err := (Config{}).Validate(); !errors.Is(err, ErrNoAddresses) {
		t.Fatalf("ErrNoAddresses kutilgan, olindi: %v", err)
	}
}

// Overlay faqat IPv6 (ADR-003). IPv4 jimgina o'tib ketmasligi kerak.
func TestConfig_RejectsIPv4(t *testing.T) {
	cases := []Config{
		{Addresses: []netip.Prefix{prefix(t, "10.0.0.1/32")}},
		{
			Addresses: []netip.Prefix{prefix(t, "fd01:cc01::1/128")},
			Routes:    []netip.Prefix{prefix(t, "10.0.0.0/8")},
		},
		// IPv4-mapped IPv6 ham IPv6 emas.
		{Addresses: []netip.Prefix{prefix(t, "::ffff:10.0.0.1/128")}},
	}

	for i, cfg := range cases {
		if err := cfg.Validate(); !errors.Is(err, ErrNotIPv6) {
			t.Errorf("holat %d: ErrNotIPv6 kutilgan, olindi: %v", i, err)
		}
	}
}

func TestConfig_AddressMustBeHostPrefix(t *testing.T) {
	cfg := Config{Addresses: []netip.Prefix{prefix(t, "2a0e:1234:1::/64")}}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "/128") {
		t.Fatalf("/128 talabi kutilgan, olindi: %v", err)
	}
}

// Normallashtirilmagan prefiksni netlink rad etadi — buni oldinroq
// ushlaymiz, aks holda xato interfeys yaratilgandan keyin chiqadi.
func TestConfig_RejectsUnmaskedRoute(t *testing.T) {
	cfg := validConfig(t)
	cfg.Routes = []netip.Prefix{prefix(t, "2a0e:1234:1::5/64")}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "normallashtirilmagan") {
		t.Fatalf("normallashtirish xatosi kutilgan, olindi: %v", err)
	}
}

func TestConfig_MTUBounds(t *testing.T) {
	cases := []struct {
		mtu   int
		valid bool
	}{
		{0, true},          // default qo'llanadi
		{DefaultMTU, true}, // 1280 — IPv6 minimumi
		{1279, false},      // undan past IPv6 uchun yaroqsiz
		{1420, true},
		{65535, true},
		{65536, false},
		{-1, false},
	}

	for _, tc := range cases {
		cfg := validConfig(t)
		cfg.MTU = tc.mtu

		err := cfg.Validate()
		if tc.valid && err != nil {
			t.Errorf("MTU %d qabul qilinishi kerak edi: %v", tc.mtu, err)
		}
		if !tc.valid && !errors.Is(err, ErrBadMTU) {
			t.Errorf("MTU %d rad etilishi kerak edi, olindi: %v", tc.mtu, err)
		}
	}
}

func TestConfig_NameValidation(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		{"", true}, // default
		{"cc0", true},
		{"cc01tun", true},
		{"abcdefghijklmno", true},   // 15 belgi — chegara
		{"abcdefghijklmnop", false}, // 16 — juda uzun
		{"cc 0", false},
		{"cc/0", false},
		{".", false},
		{"..", false},
	}

	for _, tc := range cases {
		cfg := validConfig(t)
		cfg.Name = tc.name

		err := cfg.Validate()
		if tc.valid && err != nil {
			t.Errorf("nom %q qabul qilinishi kerak edi: %v", tc.name, err)
		}
		if !tc.valid && !errors.Is(err, ErrBadName) {
			t.Errorf("nom %q rad etilishi kerak edi, olindi: %v", tc.name, err)
		}
	}
}

// Konstantalar hujjatdagi qiymatlarga mos bo'lishi kerak — ular
// tasodifan o'zgarib ketmasligi uchun.
func TestConstantsMatchSpec(t *testing.T) {
	if DefaultMTU != 1280 {
		t.Errorf("MTU 1280 bo'lishi kerak (IPv6 minimumi), %d olindi", DefaultMTU)
	}
	if RouteTable != 51820 {
		t.Errorf("routing jadvali 51820 bo'lishi kerak, %d olindi", RouteTable)
	}
	if FirewallMark != 0xca01 {
		t.Errorf("fwmark 0xca01 bo'lishi kerak, %#x olindi", FirewallMark)
	}
	if DefaultName != "cc0" {
		t.Errorf("interfeys nomi cc0 bo'lishi kerak, %q olindi", DefaultName)
	}
}

// Offset noise.HeaderSize ga teng bo'lishi kerak: datapath paketni shu
// headroom bilan o'qiydi va kripto qatlami sarlavhani aynan shu joyga
// yozadi — ko'chirishsiz.
func TestOffsetMatchesCryptoHeader(t *testing.T) {
	const noiseHeaderSize = 16 // noise.HeaderSize

	if Offset != noiseHeaderSize {
		t.Errorf("Offset %d, noise.HeaderSize %d — ular mos bo'lishi kerak",
			Offset, noiseHeaderSize)
	}

	// Platformalarning eng katta talabi (Linux virtio) 10 bayt.
	if Offset < 10 {
		t.Errorf("Offset kamida 10 bo'lishi kerak (Linux virtio), %d olindi", Offset)
	}
}
