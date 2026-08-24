//go:build linux

package tcpolicy

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// errFileExists — qdisc allaqachon mavjud.
var errFileExists = syscall.EEXIST

// protocolAll — hamma protokollar uchun filtr.
//
// tc protokolni tarmoq tartibida kutadi.
const protocolAll = uint16(unix.ETH_P_ALL<<8 | unix.ETH_P_ALL>>8)
