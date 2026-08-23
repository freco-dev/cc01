package session

import (
	"net"
	"net/netip"
)

// localEndpoints shu mashinaning underlay manzillarini yig'adi.
//
// Loopback va link-local tashlab yuboriladi: peer ularga ulana olmaydi.
// Bu STUN o'rnini bosmaydi — NAT ortidagi node uchun public manzilni
// faqat STUN topa oladi (Faza 1 davomi). Hozircha to'g'ridan-to'g'ri
// marshrutlanadigan tarmoqlar uchun yetarli.
func localEndpoints(port uint16) []netip.AddrPort {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var endpoints []netip.AddrPort

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()

			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}

			endpoints = append(endpoints, netip.AddrPortFrom(ip, port))
		}
	}

	return endpoints
}
