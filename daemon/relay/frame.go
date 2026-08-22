// Package relay P2P imkonsiz bo'lganda trafikni uzatuvchi tugunni
// va uning klientini beradi (ARCHITECTURE.md §3.3.2).
//
// Asosiy kafolat: relay **ko'r uzatuvchi**. U faqat qabul qiluvchining
// node_id sini ko'radi; foydali yuk esa ikki peer o'rtasida uchidan
// uchiga shifrlangan bo'lib qoladi va relay uni ocha olmaydi.
//
// Ikki qatlamli shifrlash:
//
//	[ node ↔ relay Noise sessiyasi          ]  ← relay ochadi
//	    [ dst_node_id | peer↔peer shifr matn ]  ← relay OCHA OLMAYDI
//
// Tashqi qatlam metadata'ni himoyalaydi: tarmoqni kuzatayotgan tomon
// kim kim bilan gaplashayotganini ko'ra olmaydi.
package relay

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// NodeIDSize — node_id uzunligi: SHA-256(pubkey).
const NodeIDSize = 32

// MaxInnerSize — uzatiladigan ichki paketning yuqori chegarasi.
//
// Chegara kerak: relay xotirasini buzuq yoki yovuz klient
// to'ldirmasligi uchun.
const MaxInnerSize = 64 * 1024

var (
	// ErrShortFrame — freym node_id uchun ham qisqa.
	ErrShortFrame = errors.New("relay: freym juda qisqa")

	// ErrInnerTooLarge — ichki paket chegaradan katta.
	ErrInnerTooLarge = errors.New("relay: ichki paket juda katta")
)

// NodeID — 32 baytli node identifikatori.
type NodeID [NodeIDSize]byte

func (n NodeID) String() string { return hex.EncodeToString(n[:]) }

// Short — log uchun qisqartirilgan ko'rinish.
func (n NodeID) Short() string { return hex.EncodeToString(n[:6]) }

// ParseNodeID hex satridan node_id o'qiydi.
func ParseNodeID(encoded string) (NodeID, error) {
	var id NodeID

	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return id, fmt.Errorf("relay: node_id dekodlash: %w", err)
	}
	if len(raw) != NodeIDSize {
		return id, fmt.Errorf("relay: node_id uzunligi %d, kutilgan %d", len(raw), NodeIDSize)
	}

	copy(id[:], raw)
	return id, nil
}

// Wrap relay freymini yasaydi: node_id + ichki paket.
//
// Jo'natishda `id` — QABUL QILUVCHI; relay uzatganda esa u
// JO'NATUVCHIga almashtiriladi. Almashtirishni relay o'zi bajaradi va
// qiymatni autentifikatsiya qilingan sessiyadan oladi — klient
// jo'natuvchi sifatida boshqa birovni ko'rsata olmaydi.
func Wrap(id NodeID, inner []byte) ([]byte, error) {
	if len(inner) > MaxInnerSize {
		return nil, fmt.Errorf("%w: %d bayt", ErrInnerTooLarge, len(inner))
	}

	frame := make([]byte, NodeIDSize+len(inner))
	copy(frame, id[:])
	copy(frame[NodeIDSize:], inner)

	return frame, nil
}

// Unwrap freymdan node_id va ichki paketni ajratadi.
//
// Qaytarilgan `inner` — kirish buferining bo'lagi, nusxa emas.
func Unwrap(frame []byte) (NodeID, []byte, error) {
	var id NodeID

	if len(frame) < NodeIDSize {
		return id, nil, fmt.Errorf("%w: %d bayt", ErrShortFrame, len(frame))
	}

	copy(id[:], frame[:NodeIDSize])
	return id, frame[NodeIDSize:], nil
}
