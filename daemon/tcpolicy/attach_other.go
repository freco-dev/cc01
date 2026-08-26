//go:build !linux

package tcpolicy

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
)

// tcDirection — Linux'dagi nusxaning o'rnini bosuvchi.
type tcDirection struct{ name string }

var (
	directionIngress = tcDirection{name: "cc01_tc_ingress"}
	directionEgress  = tcDirection{name: "cc01_tc_egress"}
)

// attachTC faqat Linux'da mavjud. Paket boshqa platformalarda ham
// QURILADI (demon macOS'da ham quriladi), lekin ishlamaydi.
func attachTC(*ebpf.Program, int, tcDirection) (func() error, error) {
	return nil, fmt.Errorf("tcpolicy: %s qo'llab-quvvatlanmaydi", runtime.GOOS)
}
