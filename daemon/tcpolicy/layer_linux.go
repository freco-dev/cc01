//go:build linux

package tcpolicy

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// arphrdNone — ARPHRD_NONE: L3 (nuqta-nuqta) qurilma, TUN shunday.
const arphrdNone = 65534

// isLayer3 interfeys L2 sarlavhasisiz ishlashini tekshiradi.
//
// Go'ning `net.Interface.HardwareAddr` maydoni yetarli emas: `lo`
// uchun u BO'SH qaytadi, garchi loopback L3 qurilma bo'lmasa ham.
// Buni test ochdi — L2 interfeysni rad etish tekshiruvi `lo` ni
// o'tkazib yubordi.
//
// Yadroning o'z qiymatini o'qiymiz: /sys/class/net/<nom>/type —
// ARPHRD_* raqami.
func isLayer3(name string) (bool, error) {
	raw, err := os.ReadFile("/sys/class/net/" + name + "/type")
	if err != nil {
		return false, fmt.Errorf("tcpolicy: interfeys turini o'qish (%s): %w", name, err)
	}

	kind, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return false, fmt.Errorf("tcpolicy: interfeys turi (%s): %w", name, err)
	}

	return kind == arphrdNone, nil
}
