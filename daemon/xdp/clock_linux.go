//go:build linux

package xdp

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// kernelTime yadro monotonik soatini nanosekundlarda qaytaradi.
//
// AYNAN shu soat kerak: XDP dasturi `bpf_ktime_get_ns()` ni
// ishlatadi va u CLOCK_MONOTONIC ga mos keladi. Devor soatini
// ishlatsak, muddatlar butunlay boshqa shkalada bo'lib, blocklist
// yozuvlari yo darhol eskirardi, yo hech qachon eskirmasdi.
func kernelTime() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("xdp: yadro soatini o'qish: %w", err)
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec), nil
}
