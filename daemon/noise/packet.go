package noise

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Paket formati (ARCHITECTURE.md §3.2.2) — WireGuard bilan mos, kichik
// kengaytmalar bilan:
//
//	 0        1        2        3        4                          N
//	 +--------+--------+--------+--------+--------+----- ... -------+
//	 | type   | rsv[3]                   | receiver_index (u32)     |
//	 +--------+--------------------------+--------------------------+
//	 | counter (u64, nonce)                                          |
//	 +---------------------------------------------------------------+
//	 | encrypted_payload (ChaCha20-Poly1305) ...                     |
//	 +---------------------------------------------------------------+
//	 | auth_tag (16 bytes)                                           |
//	 +---------------------------------------------------------------+
//
// `rsv` uchta bayt — kelajakdagi bayroqlar uchun. Hozir nol bo'lishi
// SHART EMAS (kelajakdagi versiyalar uni ishlatishi mumkin), lekin biz
// har doim nol yozamiz.

// PacketType — freym turi.
type PacketType uint8

const (
	TypeHandshakeInit PacketType = 0x01
	TypeHandshakeResp PacketType = 0x02
	TypeCookie        PacketType = 0x03
	TypeData          PacketType = 0x04
	TypeKeepalive     PacketType = 0x05
	TypeRelayWrap     PacketType = 0x06
)

func (t PacketType) String() string {
	switch t {
	case TypeHandshakeInit:
		return "handshake_init"
	case TypeHandshakeResp:
		return "handshake_resp"
	case TypeCookie:
		return "cookie"
	case TypeData:
		return "data"
	case TypeKeepalive:
		return "keepalive"
	case TypeRelayWrap:
		return "relay_wrap"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(t))
	}
}

// HeaderSize — sarlavha uzunligi: type(1) + rsv(3) + index(4) + counter(8).
const HeaderSize = 16

// TagSize — Poly1305 autentifikatsiya tegi.
const TagSize = 16

var (
	ErrShortPacket    = errors.New("noise: paket sarlavha uchun juda qisqa")
	ErrUnknownType    = errors.New("noise: paket turi noma'lum")
	ErrBufferTooSmall = errors.New("noise: bufer yetarli emas")
)

// Header — paket sarlavhasi.
type Header struct {
	Type PacketType

	// ReceiverIndex — QABUL QILUVCHI tanlagan sessiya indeksi. Jo'natuvchi
	// uni handshake paytida bilib oladi va har bir paketga yozadi, shunda
	// qabul qiluvchi kalitni public kalit bo'yicha qidirmasdan, O(1) da
	// topadi.
	ReceiverIndex uint32

	// Counter — nonce. Har bir sessiyada 0 dan boshlanadi va hech qachon
	// takrorlanmaydi (takrorlansa ChaCha20-Poly1305 buziladi).
	Counter uint64
}

// MarshalTo sarlavhani buferga yozadi va yozilgan baytlar sonini qaytaradi.
func (h Header) MarshalTo(buf []byte) (int, error) {
	if len(buf) < HeaderSize {
		return 0, ErrBufferTooSmall
	}

	buf[0] = byte(h.Type)
	buf[1], buf[2], buf[3] = 0, 0, 0 // rsv
	binary.LittleEndian.PutUint32(buf[4:8], h.ReceiverIndex)
	binary.LittleEndian.PutUint64(buf[8:16], h.Counter)

	return HeaderSize, nil
}

// ParseHeader paketning boshidan sarlavhani o'qiydi.
func ParseHeader(packet []byte) (Header, error) {
	if len(packet) < HeaderSize {
		return Header{}, ErrShortPacket
	}

	header := Header{
		Type:          PacketType(packet[0]),
		ReceiverIndex: binary.LittleEndian.Uint32(packet[4:8]),
		Counter:       binary.LittleEndian.Uint64(packet[8:16]),
	}

	switch header.Type {
	case TypeHandshakeInit, TypeHandshakeResp, TypeCookie,
		TypeData, TypeKeepalive, TypeRelayWrap:
		return header, nil
	default:
		return Header{}, fmt.Errorf("%w: 0x%02x", ErrUnknownType, packet[0])
	}
}

// Payload sarlavhadan keyingi qismni qaytaradi.
func Payload(packet []byte) ([]byte, error) {
	if len(packet) < HeaderSize {
		return nil, ErrShortPacket
	}
	return packet[HeaderSize:], nil
}
