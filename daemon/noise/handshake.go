package noise

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/flynn/noise"
)

// Handshake pattern: **Noise IK** (ARCHITECTURE.md ADR-002).
//
//	I — initiator o'z statik kalitini yuboradi (shifrlangan holda)
//	K — responderning statik kaliti initiatorga OLDINDAN ma'lum
//
// "K" aynan bizga kerak bo'lgan xususiyat: peerning public kaliti
// NetworkMap orqali oldindan keladi, shuning uchun initiator birinchi
// xabarnining o'zidayoq foydali yukni shifrlay oladi (0-RTT ga yaqin)
// va responder identifikatorini oshkor qilmaydi.
//
// Kripto to'plami: Curve25519 + BLAKE2s + ChaCha20-Poly1305.

var (
	// ErrPeerMismatch — javob kutilgan peerdan kelmadi.
	ErrPeerMismatch = errors.New("noise: peer statik kaliti mos kelmadi")

	// ErrHandshakeFailed — xabarni deshifrlab bo'lmadi.
	ErrHandshakeFailed = errors.New("noise: handshake muvaffaqiyatsiz")

	// ErrHandshakeComplete — handshake allaqachon tugagan.
	ErrHandshakeComplete = errors.New("noise: handshake allaqachon tugagan")
)

// Handshake — bir tomonlama handshake holati.
type Handshake struct {
	state     *noise.HandshakeState
	initiator bool

	// localIndex — biz tanlagan sessiya indeksi. Peer bizga yuboradigan
	// paketlarga aynan shuni yozadi.
	localIndex uint32

	// remoteIndex — peer tanlagan indeks; biz unga shuni yozamiz.
	remoteIndex uint32

	expectedPeer PublicKey
	done         bool
}

// StartInitiator handshake'ni boshlaydi. `peer` — kutilayotgan
// responderning public kaliti (IK patterni uni oldindan talab qiladi).
func StartInitiator(local *Identity, peer PublicKey) (*Handshake, error) {
	if peer.IsZero() {
		return nil, errors.New("noise: peer public kaliti berilmagan")
	}

	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: local.pair,
		PeerStatic:    peer[:],
	})
	if err != nil {
		return nil, fmt.Errorf("noise: initiator: %w", err)
	}

	index, err := randomIndex()
	if err != nil {
		return nil, err
	}

	return &Handshake{
		state:        state,
		initiator:    true,
		localIndex:   index,
		expectedPeer: peer,
	}, nil
}

// StartResponder javob beruvchi tomonni tayyorlaydi. Responder
// initiatorning kim ekanini OLDINDAN bilmaydi — u birinchi xabardan
// chiqadi.
func StartResponder(local *Identity) (*Handshake, error) {
	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: local.pair,
	})
	if err != nil {
		return nil, fmt.Errorf("noise: responder: %w", err)
	}

	index, err := randomIndex()
	if err != nil {
		return nil, err
	}

	return &Handshake{state: state, localIndex: index}, nil
}

// LocalIndex — biz tanlagan sessiya indeksi.
func (h *Handshake) LocalIndex() uint32 { return h.localIndex }

// WriteInitiation initiator yuboradigan birinchi paketni yasaydi.
//
// Paket tuzilishi: sarlavha (`Counter` maydonida bizning indeksimiz) +
// Noise IK birinchi xabari.
func (h *Handshake) WriteInitiation() ([]byte, error) {
	if !h.initiator {
		return nil, errors.New("noise: WriteInitiation faqat initiator uchun")
	}
	if h.done {
		return nil, ErrHandshakeComplete
	}

	packet := make([]byte, HeaderSize, 256)
	if _, err := (Header{
		Type:    TypeHandshakeInit,
		Counter: uint64(h.localIndex),
	}).MarshalTo(packet); err != nil {
		return nil, err
	}

	packet, _, _, err := h.state.WriteMessage(packet, nil)
	if err != nil {
		return nil, fmt.Errorf("noise: initiation yozish: %w", err)
	}
	return packet, nil
}

// ReadInitiation responder tomonda birinchi paketni qabul qiladi.
func (h *Handshake) ReadInitiation(packet []byte) error {
	if h.initiator {
		return errors.New("noise: ReadInitiation faqat responder uchun")
	}

	header, err := ParseHeader(packet)
	if err != nil {
		return err
	}
	if header.Type != TypeHandshakeInit {
		return fmt.Errorf("noise: %s kutilgan, %s olindi", TypeHandshakeInit, header.Type)
	}

	body, err := Payload(packet)
	if err != nil {
		return err
	}

	if _, _, _, err := h.state.ReadMessage(nil, body); err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	// Initiatorning indeksi sarlavhada keldi.
	h.remoteIndex = uint32(header.Counter)

	// IK'da initiatorning statik kaliti birinchi xabarda ochiladi.
	copy(h.expectedPeer[:], h.state.PeerStatic())
	return nil
}

// WriteResponse responder yuboradigan javob paketini yasaydi va sessiyani
// qaytaradi — responder uchun handshake shu bilan tugaydi.
func (h *Handshake) WriteResponse() ([]byte, *Session, error) {
	if h.initiator {
		return nil, nil, errors.New("noise: WriteResponse faqat responder uchun")
	}
	if h.done {
		return nil, nil, ErrHandshakeComplete
	}

	packet := make([]byte, HeaderSize, 256)
	if _, err := (Header{
		Type:          TypeHandshakeResp,
		ReceiverIndex: h.remoteIndex,
		Counter:       uint64(h.localIndex),
	}).MarshalTo(packet); err != nil {
		return nil, nil, err
	}

	packet, csA, csB, err := h.state.WriteMessage(packet, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("noise: javob yozish: %w", err)
	}
	if csA == nil || csB == nil {
		return nil, nil, errors.New("noise: transport kalitlari olinmadi")
	}

	h.done = true

	// Responder uchun: csA — initiatordan keladigan trafik, csB — bizniki.
	return packet, newSession(h, csB, csA), nil
}

// ReadResponse initiator tomonda javobni qabul qiladi va sessiyani qaytaradi.
func (h *Handshake) ReadResponse(packet []byte) (*Session, error) {
	if !h.initiator {
		return nil, errors.New("noise: ReadResponse faqat initiator uchun")
	}
	if h.done {
		return nil, ErrHandshakeComplete
	}

	header, err := ParseHeader(packet)
	if err != nil {
		return nil, err
	}
	if header.Type != TypeHandshakeResp {
		return nil, fmt.Errorf("noise: %s kutilgan, %s olindi", TypeHandshakeResp, header.Type)
	}
	if header.ReceiverIndex != h.localIndex {
		return nil, fmt.Errorf("noise: javob boshqa sessiyaga (%d, bizniki %d)",
			header.ReceiverIndex, h.localIndex)
	}

	body, err := Payload(packet)
	if err != nil {
		return nil, err
	}

	_, csA, csB, err := h.state.ReadMessage(nil, body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	if csA == nil || csB == nil {
		return nil, errors.New("noise: transport kalitlari olinmadi")
	}

	h.remoteIndex = uint32(header.Counter)
	h.done = true

	// Initiator uchun: csA — bizning trafik, csB — peerdan keladigani.
	return newSession(h, csA, csB), nil
}

// PeerStatic — handshake davomida aniqlangan peer public kaliti.
func (h *Handshake) PeerStatic() PublicKey { return h.expectedPeer }

func randomIndex() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("noise: indeks yaratish: %w", err)
	}

	index := binary.LittleEndian.Uint32(buf[:])
	if index == 0 {
		// 0 — "indeks yo'q" ma'nosini bildiradi, uni ishlatmaymiz.
		index = 1
	}
	return index, nil
}
