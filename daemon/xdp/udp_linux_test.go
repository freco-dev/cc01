//go:build linux

package xdp

import (
	"os/exec"
	"testing"
)

// sendUDPFrom netns'dan berilgan MANBA porti bilan UDP paketi
// yuboradi.
//
// `socat` yoki `nc` ishlatilmaydi: ular manba portini tanlashga
// har doim ham ruxsat bermaydi. `ip netns exec` ichida Python ham
// bo'lmasligi mumkin, shuning uchun eng oddiy yo'l — `nc -p`.
func sendUDPFrom(t *testing.T, sport int) {
	t.Helper()

	err := exec.Command("ip", "netns", "exec", testNS,
		"sh", "-c", "echo cc01 | nc -u -w1 -p "+itoa(sport)+" "+localAddr+" 9").Run()
	if err != nil {
		t.Skipf("UDP yuborilmadi (nc yo'qmi?): %v", err)
	}
}

// sendUDPTo berilgan MAQSAD portiga UDP paketi yuboradi.
func sendUDPTo(t *testing.T, dport int) {
	t.Helper()

	err := exec.Command("ip", "netns", "exec", testNS,
		"sh", "-c", "echo cc01 | nc -u -w1 "+localAddr+" "+itoa(dport)).Run()
	if err != nil {
		t.Skipf("UDP yuborilmadi (nc yo'qmi?): %v", err)
	}
}
