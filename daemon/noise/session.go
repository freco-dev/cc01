package noise

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/flynn/noise"
)

// Rekey siyosati (ARCHITECTURE.md §3.2.2).
const (
	// RekeyAfterTime — sessiya shu muddatdan keyin yangilanadi. Qisqa
	// muddat PFS oynasini kichraytiradi: kalit sizib chiqsa u faqat shu
	// oyna ichidagi trafikni ochadi.
	RekeyAfterTime = 120 * time.Second

	// RejectAfterTime — bu muddatdan keyin sessiya butunlay ishlatilmaydi.
	RejectAfterTime = 3 * RekeyAfterTime

	// RekeyAfterMessages — nonce tugab qolmasligi uchun chegara. 2^60 —
	// 2^64 dan ancha past, ya'ni rekey ulgurishi uchun katta zaxira bor.
	RekeyAfterMessages = uint64(1) << 60
)

var (
	// ErrSessionExpired — sessiya muddati o'tgan.
	ErrSessionExpired = errors.New("noise: sessiya muddati o'tgan")

	// ErrNonceExhausted — nonce tugadi; rekey qilinmagan.
	ErrNonceExhausted = errors.New("noise: nonce tugadi")

	// ErrReplay — paket takroriy yoki juda eski.
	ErrReplay = errors.New("noise: takroriy paket")

	// ErrDecryptFailed — AEAD tekshiruvi o'tmadi.
	ErrDecryptFailed = errors.New("noise: deshifrlash muvaffaqiyatsiz")

	// ErrIndexMismatch — paket boshqa sessiyaga tegishli.
	ErrIndexMismatch = errors.New("noise: sessiya indeksi mos kelmadi")
)

// Session — o'rnatilgan transport sessiyasi: ikkita yo'nalishli kalit,
// nonce hisoblagichi va replay oynasi.
//
// Session bir vaqtda bir nechta goroutine tomonidan ishlatilishi mumkin.
type Session struct {
	localIndex  uint32
	remoteIndex uint32
	peer        PublicKey
	initiator   bool
	created     time.Time

	sendMu sync.Mutex
	send   *noise.CipherState
	nonce  uint64

	recvMu sync.Mutex
	recv   *noise.CipherState
	replay *ReplayWindow
}

func newSession(h *Handshake, send, recv *noise.CipherState) *Session {
	return &Session{
		localIndex:  h.localIndex,
		remoteIndex: h.remoteIndex,
		peer:        h.expectedPeer,
		initiator:   h.initiator,
		created:     time.Now(),
		send:        send,
		recv:        recv,
		replay:      NewReplayWindow(),
	}
}

// LocalIndex — bizning sessiya indeksimiz; peer bizga yozadigan paketlarda
// shu bo'ladi.
func (s *Session) LocalIndex() uint32 { return s.localIndex }

// RemoteIndex — peerning indeksi; biz unga yozadigan paketlarda shu bo'ladi.
func (s *Session) RemoteIndex() uint32 { return s.remoteIndex }

// Peer — peerning doimiy public kaliti.
func (s *Session) Peer() PublicKey { return s.peer }

// IsInitiator — sessiyani biz boshlaganmizmi.
//
// Rekey'ni FAQAT initiator boshlaydi (ARCHITECTURE.md §3.5): ikkala tomon
// bir vaqtda boshlasa ikkita sessiya paydo bo'lib, "thundering herd"
// hosil qiladi.
func (s *Session) IsInitiator() bool { return s.initiator }

// Age — sessiya yoshi.
func (s *Session) Age() time.Duration { return time.Since(s.created) }

// NeedsRekey — vaqt yoki paket soni bo'yicha yangilash kerakmi.
func (s *Session) NeedsRekey() bool {
	if s.Age() >= RekeyAfterTime {
		return true
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.nonce >= RekeyAfterMessages
}

// Expired — sessiya butunlay ishlatilmaydigan holatga o'tganmi.
func (s *Session) Expired() bool { return s.Age() >= RejectAfterTime }

// Seal foydali yukni shifrlaydi va to'liq paketni qaytaradi.
//
// `packetType` odatda TypeData yoki TypeKeepalive.
func (s *Session) Seal(packetType PacketType, plaintext []byte) ([]byte, error) {
	if s.Expired() {
		return nil, ErrSessionExpired
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	if s.nonce >= ^uint64(0)-1 {
		return nil, ErrNonceExhausted
	}

	counter := s.nonce
	s.nonce++

	packet := make([]byte, HeaderSize, HeaderSize+len(plaintext)+TagSize)
	if _, err := (Header{
		Type:          packetType,
		ReceiverIndex: s.remoteIndex,
		Counter:       counter,
	}).MarshalTo(packet); err != nil {
		return nil, err
	}

	// Sarlavha AEAD uchun qo'shimcha autentifikatsiya ma'lumoti (AD):
	// shunda indeks va hisoblagichni ham o'zgartirib bo'lmaydi.
	//
	// CipherState o'z ichki nonce'ini yuritadi; biz uni paketdagi
	// hisoblagichga tenglashtiramiz, chunki simda aynan shu ketadi.
	s.send.SetNonce(counter)

	sealed, err := s.send.Encrypt(packet, packet[:HeaderSize], plaintext)
	if err != nil {
		return nil, fmt.Errorf("noise: shifrlash: %w", err)
	}
	return sealed, nil
}

// Open paketni tekshiradi va deshifrlaydi.
//
// Tartib muhim: avval AEAD, keyin replay. Aks holda tajovuzkor soxta
// hisoblagichlar bilan oynani oldinga surib, haqiqiy paketlarni "eski"
// qilib qo'ya olardi.
func (s *Session) Open(packet []byte) (Header, []byte, error) {
	header, err := ParseHeader(packet)
	if err != nil {
		return Header{}, nil, err
	}

	if header.ReceiverIndex != s.localIndex {
		return header, nil, fmt.Errorf("%w: %d (bizniki %d)",
			ErrIndexMismatch, header.ReceiverIndex, s.localIndex)
	}

	if s.Expired() {
		return header, nil, ErrSessionExpired
	}

	body, err := Payload(packet)
	if err != nil {
		return header, nil, err
	}

	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	// SetNonce — noise/cipherstate o'z ichki hisoblagichini ishlatadi,
	// bizda esa nonce paketda keladi (paketlar yo'qolishi va qayta
	// tartiblanishi mumkin).
	s.recv.SetNonce(header.Counter)

	plaintext, err := s.recv.Decrypt(nil, packet[:HeaderSize], body)
	if err != nil {
		return header, nil, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}

	// AEAD o'tdi — endi paket haqiqiy, replay oynasini yangilash xavfsiz.
	if !s.replay.Accept(header.Counter) {
		return header, nil, fmt.Errorf("%w: counter=%d", ErrReplay, header.Counter)
	}

	return header, plaintext, nil
}
