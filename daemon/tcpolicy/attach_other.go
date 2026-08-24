//go:build !linux

package tcpolicy

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
)

// attachIngress faqat Linux'da mavjud. Paket boshqa platformalarda
// ham QURILADI (demon macOS'da ham quriladi), lekin ishlamaydi.
func attachIngress(*ebpf.Program, int) (func() error, error) {
	return nil, fmt.Errorf("tcpolicy: %s qo'llab-quvvatlanmaydi", runtime.GOOS)
}
