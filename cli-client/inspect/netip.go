package inspect

import "net/netip"

// netipParse — manzilni tahlil qiladi.
//
// Alohida yordamchi: `net.ParseIP` eskirgan va u nol qiymat bilan
// xatoni ajratmaydi.
func netipParse(host string) (netip.Addr, error) {
	return netip.ParseAddr(host)
}
