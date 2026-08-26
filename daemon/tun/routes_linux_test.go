//go:build linux

package tun

import (
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

// listTableRoutes ajratilgan jadvaldagi marshrutlar sonini qaytaradi.
func listTableRoutes() (int, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: RouteTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, err
	}
	return len(routes), nil
}

// SetRoutes yadroda haqiqatda marshrut qo'shishi va o'chirishi kerak.
// Rekonsilyator testlari soxta sink bilan ishlaydi — netlink qismini
// faqat shu yerda tekshirib bo'ladi.
func TestSetRoutes_AddsAndRemovesInKernel(t *testing.T) {
	requirePrivileges(t)

	device := createTestDevice(t)

	extra := netip.MustParsePrefix("2a0e:1234:5678::/48")
	base := netip.MustParsePrefix(testNet)

	diff, err := device.SetRoutes([]netip.Prefix{base, extra})
	if err != nil {
		t.Fatalf("SetRoutes: %v", err)
	}
	if !slices.Contains(diff.Added, extra) {
		t.Fatalf("qo'shilgan marshrut diffda yo'q: %s", diff)
	}

	kernel, err := listRoutes(device.Name())
	if err != nil {
		t.Fatalf("listRoutes: %v", err)
	}
	if !slices.Contains(kernel, extra) {
		t.Fatalf("marshrut yadroda yo'q: %v", kernel)
	}

	// Endi uni kerakli holatdan olib tashlaymiz.
	diff, err = device.SetRoutes([]netip.Prefix{base})
	if err != nil {
		t.Fatalf("SetRoutes (o'chirish): %v", err)
	}
	if !slices.Contains(diff.Removed, extra) {
		t.Fatalf("o'chirilgan marshrut diffda yo'q: %s", diff)
	}

	kernel, err = listRoutes(device.Name())
	if err != nil {
		t.Fatalf("listRoutes: %v", err)
	}
	if slices.Contains(kernel, extra) {
		t.Fatalf("orphan marshrut qoldi: %v", kernel)
	}
	if !slices.Contains(kernel, base) {
		t.Fatalf("base marshrut yo'qolgan: %v", kernel)
	}
}

// Bir xil holat ikkinchi marta qo'llanganda yadroga tegilmasligi kerak.
func TestSetRoutes_IsIdempotent(t *testing.T) {
	requirePrivileges(t)

	device := createTestDevice(t)
	desired := []netip.Prefix{netip.MustParsePrefix(testNet)}

	if _, err := device.SetRoutes(desired); err != nil {
		t.Fatalf("SetRoutes: %v", err)
	}

	diff, err := device.SetRoutes(desired)
	if err != nil {
		t.Fatalf("SetRoutes (takror): %v", err)
	}
	if !diff.Empty() {
		t.Errorf("takroriy chaqiruv o'zgarish ko'rsatdi: %s", diff)
	}
}

// Create qo'ygan marshrutlar boshlang'ich holat sifatida hisoblanishi
// kerak — aks holda birinchi rekonsiliatsiya ularni "yangi" deb
// qayta qo'yadi.
func TestSetRoutes_CreateRoutesAreTheBaseline(t *testing.T) {
	requirePrivileges(t)

	device := createTestDevice(t)

	diff, err := device.SetRoutes([]netip.Prefix{netip.MustParsePrefix(testNet)})
	if err != nil {
		t.Fatalf("SetRoutes: %v", err)
	}
	if !diff.Empty() {
		t.Errorf("Create qo'ygan marshrut qayta qo'yildi: %s", diff)
	}
}

// Close hamma marshrutni tozalaydi — DoD: 0 orphan.
func TestSetRoutes_CloseLeavesNothing(t *testing.T) {
	requirePrivileges(t)

	device, err := Create(Config{
		Name:      "cc0test",
		Addresses: []netip.Prefix{netip.MustParsePrefix(testLocal)},
		Routes:    []netip.Prefix{netip.MustParsePrefix(testNet)},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := device.SetRoutes([]netip.Prefix{
		netip.MustParsePrefix(testNet),
		netip.MustParsePrefix("2a0e:1234:5678::/48"),
		netip.MustParsePrefix("2a0e:9999::/32"),
	}); err != nil {
		t.Fatalf("SetRoutes: %v", err)
	}

	if err := device.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	remaining, err := listTableRoutes()
	if err != nil {
		t.Fatalf("listTableRoutes: %v", err)
	}
	if remaining != 0 {
		t.Errorf("Close dan keyin %d ta marshrut qoldi, 0 kutilgan edi", remaining)
	}
}

// DEV_SPEC §3.3: foydalanuvchi marshrutlariga HECH QACHON tegilmaydi.
//
// Ajratilgan jadval ham daxlsiz emas — u yerga kimdir qo'lda marshrut
// qo'shgan bo'lsa, rekonsiliatsiya uni "ortiqcha" deb o'chirmasligi
// kerak. Farq protokolda: `ip route add` RTPROT_BOOT qo'yadi, biz
// RTPROT_STATIC yozamiz.
func TestSetRoutes_LeavesForeignRoutesAlone(t *testing.T) {
	requirePrivileges(t)

	device := createTestDevice(t)

	link, err := netlink.LinkByName(device.Name())
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}

	foreign := netip.MustParsePrefix("2a0e:dead:beef::/48")
	manual := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   foreign.Addr().AsSlice(),
			Mask: net.CIDRMask(foreign.Bits(), 128),
		},
		Table:    RouteTable,
		Protocol: netlink.RouteProtocol(syscall.RTPROT_BOOT),
	}
	if err := netlink.RouteAdd(manual); err != nil {
		t.Fatalf("qo'lda marshrut qo'shish: %v", err)
	}

	// Rekonsiliatsiya faqat base'ni xohlaydi — begona marshrut
	// "ortiqcha" ko'rinadi, lekin unga tegilmasligi kerak.
	if _, err := device.SetRoutes([]netip.Prefix{netip.MustParsePrefix(testNet)}); err != nil {
		t.Fatalf("SetRoutes: %v", err)
	}

	all, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: RouteTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("RouteListFiltered: %v", err)
	}

	found := false
	for i := range all {
		if all[i].Dst != nil && all[i].Dst.String() == foreign.String() {
			found = true
		}
	}
	if !found {
		t.Error("begona marshrut o'chirib yuborildi")
	}

	_ = netlink.RouteDel(manual)
}
