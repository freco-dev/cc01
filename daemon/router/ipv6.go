package router

import (
	"errors"
	"fmt"
	"net/netip"
)

// IPv6 sarlavhasi (RFC 8200) — bizga faqat manba va manzil kerak.
//
//	 0                   1                   2                   3
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|Version| Traffic Class |           Flow Label                  |
//	+-------+---------------+---------------------------------------+
//	|         Payload Length        |  Next Header  |   Hop Limit   |
//	+-------------------------------+---------------+---------------+
//	|                         Source Address (16)                   |
//	+---------------------------------------------------------------+
//	|                       Destination Address (16)                |
//	+---------------------------------------------------------------+
const (
	ipv6HeaderLen = 40
	srcOffset     = 8
	dstOffset     = 24
)

var (
	// ErrShortPacket — paket IPv6 sarlavhasi uchun ham qisqa.
	ErrShortPacket = errors.New("router: paket juda qisqa")

	// ErrNotIPv6 — overlay faqat IPv6 (ADR-003). IPv4 paket bu yerga
	// tushsa — bu marshrutlash sozlamasidagi xato.
	ErrNotIPv6 = errors.New("router: IPv6 emas")
)

// endpoints paketdan manba va manzil manzillarini oladi.
func endpoints(packet []byte) (src, dst netip.Addr, err error) {
	if len(packet) < ipv6HeaderLen {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("%w: %d bayt", ErrShortPacket, len(packet))
	}

	version := packet[0] >> 4
	if version != 6 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("%w: versiya %d", ErrNotIPv6, version)
	}

	src = netip.AddrFrom16([16]byte(packet[srcOffset : srcOffset+16]))
	dst = netip.AddrFrom16([16]byte(packet[dstOffset : dstOffset+16]))

	return src, dst, nil
}
