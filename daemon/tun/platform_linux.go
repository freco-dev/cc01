//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/vishvananda/netlink"
)

// configure interfeysni ko'taradi, manzillarni qo'yadi va marshrutlarni
// AJRATILGAN jadvalga yozadi (DEV_SPEC §3.3).
func configure(name string, cfg Config) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("tun: interfeys topilmadi (%s): %w", name, err)
	}

	if err := netlink.LinkSetMTU(link, cfg.MTU); err != nil {
		return fmt.Errorf("tun: MTU: %w", err)
	}
	if err := netlink.LinkSetTxQLen(link, 1000); err != nil {
		return fmt.Errorf("tun: txqlen: %w", err)
	}

	if err := tuneSysctl(name); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("tun: interfeysni ko'tarish: %w", err)
	}

	for _, prefix := range cfg.Addresses {
		if err := addAddress(link, prefix); err != nil {
			return err
		}
	}

	for _, prefix := range cfg.Routes {
		if err := addRoute(link, prefix); err != nil {
			return err
		}
	}

	return addRules()
}

func addAddress(link netlink.Link, prefix netipPrefix) error {
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), 128),
		},
		// NODAD majburiy: overlay'da Duplicate Address Detection ma'nosiz
		// (manzillarni IPAM beradi, to'qnashuv bo'lishi mumkin emas) va u
		// interfeys ko'tarilishini ~1 soniyaga kechiktiradi.
		Flags: syscall.IFA_F_NODAD | syscall.IFA_F_PERMANENT,
	}

	if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("tun: manzil qo'shish (%v): %w", prefix, err)
	}
	return nil
}

func addRoute(link netlink.Link, prefix netipPrefix) error {
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), 128),
		},
		Table:    RouteTable,
		Protocol: netlink.RouteProtocol(syscall.RTPROT_STATIC),
		Priority: 100,
	}

	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("tun: marshrut qo'shish (%v): %w", prefix, err)
	}
	return nil
}

// addRules policy routing qoidalarini o'rnatadi.
//
//	5210: cc01d o'zi yubormagan paketlar ajratilgan jadvaldan qidiriladi
//	5211: asosiy jadvaldagi default marshrut bosib qolinmaydi
//
// `not fwmark` — rekursiyaning oldini oladi: cc01d shifrlangan paketni
// UDP orqali yuborganda, u qayta overlay'ga tushmasligi kerak.
func addRules() error {
	lookup := netlink.NewRule()
	lookup.Priority = RulePriorityLookup
	lookup.Family = netlink.FAMILY_V6
	lookup.Mark = FirewallMark
	lookup.Invert = true
	lookup.Table = RouteTable

	if err := replaceRule(lookup); err != nil {
		return fmt.Errorf("tun: lookup qoidasi: %w", err)
	}

	suppress := netlink.NewRule()
	suppress.Priority = RulePrioritySuppress
	suppress.Family = netlink.FAMILY_V6
	suppress.Table = syscall.RT_TABLE_MAIN
	suppress.SuppressPrefixlen = 0

	if err := replaceRule(suppress); err != nil {
		return fmt.Errorf("tun: suppress qoidasi: %w", err)
	}
	return nil
}

func replaceRule(rule *netlink.Rule) error {
	// RuleAdd takroriy qoida qo'shib yuboradi, shuning uchun avval
	// o'chiramiz. Mavjud bo'lmasa xato — normal holat.
	_ = netlink.RuleDel(rule)
	return netlink.RuleAdd(rule)
}

// tuneSysctl interfeysga xos yadro sozlamalari (DEV_SPEC §3.2).
//
// Faqat SHU interfeys uchun yoziladi — tizim bo'ylab sozlamalarga
// tegilmaydi.
func tuneSysctl(name string) error {
	settings := []struct{ key, value string }{
		{"disable_ipv6", "0"},
		// Router Advertisement va autoconf overlay'da keraksiz: manzil
		// IPAM'dan keladi, yadro o'zi qo'shishi kerak emas.
		{"accept_ra", "0"},
		{"autoconf", "0"},
		// Subnet-router rejimi uchun (ARCHITECTURE.md §3.2.1).
		{"forwarding", "1"},
	}

	for _, setting := range settings {
		path := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/%s", name, setting.key)
		if err := os.WriteFile(path, []byte(setting.value), 0o644); err != nil {
			// Ba'zi konteynerlarda /proc/sys faqat o'qish uchun
			// mount qilingan. Bu halokatli emas — ogohlantirib o'tamiz.
			if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) {
				continue
			}
			return fmt.Errorf("tun: sysctl %s: %w", setting.key, err)
		}
	}
	return nil
}

// cleanup biz qo'shgan hamma narsani olib tashlaydi.
//
// FAQAT ajratilgan jadval va o'z qoidalarimizga tegamiz — foydalanuvchining
// marshrutlariga hech qachon (DEV_SPEC §3.3).
func cleanup(name string) error {
	var errs []error

	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: RouteTable}, netlink.RT_FILTER_TABLE)
	if err == nil {
		for i := range routes {
			if err := netlink.RouteDel(&routes[i]); err != nil {
				errs = append(errs, fmt.Errorf("marshrut %v: %w", routes[i].Dst, err))
			}
		}
	}

	for _, priority := range []int{RulePriorityLookup, RulePrioritySuppress} {
		rule := netlink.NewRule()
		rule.Priority = priority
		rule.Family = netlink.FAMILY_V6
		if err := netlink.RuleDel(rule); err != nil && !errors.Is(err, syscall.ENOENT) {
			errs = append(errs, fmt.Errorf("qoida %d: %w", priority, err))
		}
	}

	_ = name
	return errors.Join(errs...)
}
