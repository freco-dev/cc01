//go:build linux

package tcpolicy

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/freco-dev/cc01/daemon/tun"
)

// testDeviceMTU berilgan MTU bilan TUN qurilmasini yaratadi.
//
// MSS sinovi uchun MTU 1280 dan KATTA bo'lishi kerak: yadro MSS ni
// interfeys MTU'sidan hisoblaydi va 1280 da u allaqachon 1220
// bo'lardi, ya'ni kichraytirish umuman ishlamas edi va test hech
// narsani tekshirmasdi.
func testDeviceMTU(t *testing.T, mtu int) *tun.Device {
	t.Helper()

	device, err := tun.Create(tun.Config{
		Name:      "cc0pol",
		MTU:       mtu,
		Addresses: []netip.Prefix{netip.MustParsePrefix(localAddr + "/128")},
		Routes:    []netip.Prefix{netip.MustParsePrefix(testNet)},
	})
	if err != nil {
		t.Skipf("TUN yaratilmadi: %v", err)
	}

	t.Cleanup(func() { _ = device.Close() })
	return device
}

// dialPeer peerga TCP ulanishga urinadi.
//
// Xom soket EMAS: IPv6'da IPPROTO_RAW o'z sarlavhangni yozishga
// ruxsat bermaydi va urinish `invalid argument` bilan tugaydi —
// testlar o'shanda JIMGINA o'tkazib yuborilardi.
//
// Haqiqiy ulanish esa yadroning o'z yo'lidan o'tadi: u SYN ni
// haqiqiy MSS opsiyasi bilan yasaydi va uni cc0 orqali chiqaradi.
// Hech kim javob bermaydi, bizga esa faqat chiqqan SYN kerak.
func dialPeer(t *testing.T, port int) {
	t.Helper()

	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.Dial("tcp6", net.JoinHostPort(peerAddr, itoa(port)))
	if err == nil {
		_ = conn.Close()
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// readTCPFromDevice TUN'dan chiqqan birinchi TCP paketini o'qiydi.
//
// TUN'ga yozish — yadroga KIRUVCHI paket, undan o'qish esa yadrodan
// CHIQUVCHI paket. Egress filtri aynan shu yo'lda ishlaydi.
func readTCPFromDevice(t *testing.T, device *tun.Device, timeout time.Duration) []byte {
	t.Helper()

	found := make(chan []byte, 1)

	go func() {
		bufs, sizes := device.NewBuffers()

		for {
			count, err := device.Read(bufs, sizes, tun.Offset)
			if err != nil {
				return
			}

			for i := range count {
				packet := bufs[i][tun.Offset : tun.Offset+sizes[i]]

				// TUN'da ICMPv6 router solicitation kabi shovqin
				// ham bor — faqat TCP kerak.
				if len(packet) > 40 && packet[6] == 6 {
					copied := make([]byte, len(packet))
					copy(copied, packet)
					select {
					case found <- copied:
					default:
					}
					return
				}
			}
		}
	}()

	select {
	case packet := <-found:
		return packet
	case <-time.After(timeout):
		return nil
	}
}
