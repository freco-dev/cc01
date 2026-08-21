//go:build linux

package tun

import "github.com/vishvananda/netlink"

// listTableRoutes ajratilgan jadvaldagi marshrutlar sonini qaytaradi.
func listTableRoutes() (int, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: RouteTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, err
	}
	return len(routes), nil
}
