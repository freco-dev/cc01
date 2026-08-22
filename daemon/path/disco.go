package path

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// Disco xabari — yo'l sifatini o'lchash uchun eng kichik ping/pong.
//
//	kind  uint8    0x01 ping, 0x02 pong
//	nonce uint64   so'rovni javobi bilan bog'laydi
//
// Nonce kerak: bir vaqtda bir nechta yo'l sinalishi mumkin va javob
// qaysi so'rovga tegishli ekanini bilish shart. Vaqt tamg'asi
// yuborilmaydi — RTT ni jo'natuvchi o'zi o'lchaydi, ya'ni soatlar
// mos kelishi talab qilinmaydi.
const (
	DiscoSize = 9

	discoPing uint8 = 0x01
	discoPong uint8 = 0x02
)

// ErrBadDisco — xabar buzuq.
var ErrBadDisco = errors.New("path: disco xabari yaroqsiz")

// DiscoKind — ping yoki pong.
type DiscoKind uint8

const (
	Ping DiscoKind = iota
	Pong
)

func (k DiscoKind) String() string {
	if k == Pong {
		return "pong"
	}
	return "ping"
}

// NewNonce yangi tasodifiy nonce yaratadi.
func NewNonce() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("path: nonce: %w", err)
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// EncodeDisco xabarni baytlarga aylantiradi.
func EncodeDisco(kind DiscoKind, nonce uint64) []byte {
	payload := make([]byte, DiscoSize)

	if kind == Pong {
		payload[0] = discoPong
	} else {
		payload[0] = discoPing
	}
	binary.LittleEndian.PutUint64(payload[1:], nonce)

	return payload
}

// DecodeDisco xabarni o'qiydi.
func DecodeDisco(payload []byte) (DiscoKind, uint64, error) {
	if len(payload) != DiscoSize {
		return 0, 0, fmt.Errorf("%w: uzunlik %d", ErrBadDisco, len(payload))
	}

	var kind DiscoKind
	switch payload[0] {
	case discoPing:
		kind = Ping
	case discoPong:
		kind = Pong
	default:
		return 0, 0, fmt.Errorf("%w: turi %#x", ErrBadDisco, payload[0])
	}

	return kind, binary.LittleEndian.Uint64(payload[1:]), nil
}
