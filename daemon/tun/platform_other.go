//go:build !linux && !darwin

package tun

import (
	"fmt"
	"runtime"
)

// Bu platformada TUN sozlash amalga oshirilmagan (DEV_SPEC §3.2:
// Windows uchun Wintun + netsh, mobil uchun NetworkExtension/VpnService
// alohida ishlar).
func configure(string, Config) error {
	return fmt.Errorf("tun: %s qo'llab-quvvatlanmaydi", runtime.GOOS)
}

func cleanup(string) error { return nil }
