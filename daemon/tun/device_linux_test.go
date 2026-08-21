//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// Bu testlar haqiqiy TUN qurilmasi yaratadi, ya'ni CAP_NET_ADMIN va
// /dev/net/tun talab qiladi. Konteynerda ishga tushirish:
//
//	docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
//	  -v "$PWD":/src -w /src/daemon golang:1.25 \
//	  go test -count=1 ./tun/...
func requirePrivileges(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("TUN yaratish uchun root kerak")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("/dev/net/tun mavjud emas: %v", err)
	}
}

const (
	testLocal = "fd00:cc01:7e57::1/128"
	testPeer  = "fd00:cc01:7e57::2"
	testNet   = "fd00:cc01:7e57::/64"
)

func createTestDevice(t *testing.T) *Device {
	t.Helper()

	device, err := Create(Config{
		Name:      "cc0test",
		Addresses: []netip.Prefix{netip.MustParsePrefix(testLocal)},
		Routes:    []netip.Prefix{netip.MustParsePrefix(testNet)},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	t.Cleanup(func() {
		if err := device.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return device
}

func TestDevice_CreateAndConfigure(t *testing.T) {
	requirePrivileges(t)

	device := createTestDevice(t)

	if device.Name() != "cc0test" {
		t.Errorf("nom: cc0test kutilgan, %q olindi", device.Name())
	}

	mtu, err := device.MTU()
	if err != nil {
		t.Fatalf("MTU: %v", err)
	}
	if mtu != DefaultMTU {
		t.Errorf("MTU: %d kutilgan, %d olindi", DefaultMTU, mtu)
	}

	// Manzil interfeysga haqiqatan qo'yilganmi.
	iface, err := net.InterfaceByName(device.Name())
	if err != nil {
		t.Fatalf("InterfaceByName: %v", err)
	}
	if iface.Flags&net.FlagUp == 0 {
		t.Error("interfeys ko'tarilmagan")
	}

	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatalf("Addrs: %v", err)
	}

	want := netip.MustParsePrefix(testLocal).Addr()
	var found bool
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if got, ok := netip.AddrFromSlice(ipNet.IP); ok && got.Unmap() == want {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("%v manzili topilmadi, mavjudlari: %v", want, addrs)
	}
}

// Faza 1 qabul mezoni: TUN orqali IPv6 paket o'tishi.
//
// Yadro ICMPv6 echo request'ni TUN'ga yo'naltiradi, biz uni Go'da
// o'qiymiz, javob yasab qaytaramiz — va yadro javobni socket'ga yetkazadi.
// Bu marshrut, manzil va ikki tomonlama I/O ning hammasini isbotlaydi.
func TestDevice_ICMPv6RoundTrip(t *testing.T) {
	requirePrivileges(t)

	device := createTestDevice(t)
	local := netip.MustParsePrefix(testLocal).Addr()
	peer := netip.MustParseAddr(testPeer)

	done := make(chan struct{})
	defer close(done)

	// TUN'dan o'qib, echo request'larga javob beruvchi.
	//
	// Buferlar Offset headroom bilan ajratiladi — platformalar shuni
	// talab qiladi (Offset izohiga qarang).
	go func() {
		bufs, sizes := device.NewBuffers()

		// Javob uchun ham headroom kerak.
		out := make([]byte, Offset+DefaultMTU)

		for {
			select {
			case <-done:
				return
			default:
			}

			count, err := device.Read(bufs, sizes, Offset)
			if err != nil {
				return
			}

			for i := range count {
				packet := bufs[i][Offset : Offset+sizes[i]]

				reply := buildEchoReply(packet)
				if reply == nil {
					continue
				}

				copy(out[Offset:], reply)
				if _, err := device.Write([][]byte{out[:Offset+len(reply)]}, Offset); err != nil {
					return
				}
			}
		}
	}()

	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", local.String())
	if err != nil {
		t.Fatalf("ICMPv6 socket: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	body := &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("cc01-tun-test")}
	request, err := (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: body}).
		Marshal(icmp.IPv6PseudoHeader(local.AsSlice(), peer.AsSlice()))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if _, err := conn.WriteTo(request, &net.IPAddr{IP: peer.AsSlice()}); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("javob kelmadi: %v", err)
		}

		message, err := icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), buf[:n])
		if err != nil {
			continue
		}
		if message.Type != ipv6.ICMPTypeEchoReply {
			continue
		}

		echo, ok := message.Body.(*icmp.Echo)
		if !ok || echo.Seq != 1 {
			continue
		}
		if string(echo.Data) != "cc01-tun-test" {
			t.Fatalf("javob mazmuni: %q", echo.Data)
		}
		if from.String() != peer.String() {
			t.Fatalf("javob %s dan kutilgan, %s dan keldi", peer, from)
		}
		return
	}
}

// Close biz qo'shgan marshrutlarni tozalashi kerak — orphan qolmasin
// (DEV_SPEC §3.3, §7.1 majburiy stsenariy 7).
func TestDevice_CloseRemovesRoutes(t *testing.T) {
	requirePrivileges(t)

	device, err := Create(Config{
		Name:      "cc0clean",
		Addresses: []netip.Prefix{netip.MustParsePrefix("fd00:cc01:c1ea::1/128")},
		Routes:    []netip.Prefix{netip.MustParsePrefix("fd00:cc01:c1ea::/64")},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if count := countTableRoutes(t); count == 0 {
		t.Fatal("marshrut ajratilgan jadvalga yozilmadi")
	}

	if err := device.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if count := countTableRoutes(t); count != 0 {
		t.Errorf("Close'dan keyin %d ta orphan marshrut qoldi", count)
	}
}

// buildEchoReply kelgan IPv6 paketni tekshiradi va agar u ICMPv6 echo
// request bo'lsa, javob paketini yasaydi.
func buildEchoReply(packet []byte) []byte {
	const ipv6HeaderLen = 40

	if len(packet) < ipv6HeaderLen {
		return nil
	}
	if packet[0]>>4 != 6 {
		return nil
	}
	// Next Header — ICMPv6 (58). Extension header'larni qo'llab-quvvatlash
	// bu testga kerak emas.
	if packet[6] != 58 {
		return nil
	}

	src, ok := netip.AddrFromSlice(packet[8:24])
	if !ok {
		return nil
	}
	dst, ok := netip.AddrFromSlice(packet[24:40])
	if !ok {
		return nil
	}

	message, err := icmp.ParseMessage(ipv6.ICMPTypeEchoRequest.Protocol(), packet[ipv6HeaderLen:])
	if err != nil || message.Type != ipv6.ICMPTypeEchoRequest {
		return nil
	}

	// Javobda manba va manzil almashadi.
	payload, err := (&icmp.Message{Type: ipv6.ICMPTypeEchoReply, Body: message.Body}).
		Marshal(icmp.IPv6PseudoHeader(dst.AsSlice(), src.AsSlice()))
	if err != nil {
		return nil
	}

	reply := make([]byte, ipv6HeaderLen+len(payload))
	reply[0] = 6 << 4
	binary.BigEndian.PutUint16(reply[4:6], uint16(len(payload)))
	reply[6] = 58 // Next Header: ICMPv6
	reply[7] = 64 // Hop Limit
	copy(reply[8:24], dst.AsSlice())
	copy(reply[24:40], src.AsSlice())
	copy(reply[ipv6HeaderLen:], payload)

	return reply
}

func countTableRoutes(t *testing.T) int {
	t.Helper()

	routes, err := listTableRoutes()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marshrutlarni o'qish: %v", err)
	}
	return routes
}
