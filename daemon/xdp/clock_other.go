//go:build !linux

package xdp

import (
	"fmt"
	"runtime"
)

// kernelTime faqat Linux'da mavjud. Bu paket boshqa platformalarda
// ham QURILADI (demon macOS'da ham quriladi), lekin ishlamaydi.
func kernelTime() (uint64, error) {
	return 0, fmt.Errorf("%w: %s", ErrUnsupported, runtime.GOOS)
}
