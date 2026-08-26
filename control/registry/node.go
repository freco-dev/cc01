// Package registry nodelarni ro'yxatga oladi va ularga NetworkMap
// tarqatadi (ARCHITECTURE.md §3.1.2).
//
// Asosiy g'oya — **delta sync**. To'liq map 500 peerda ~200 KB bo'ladi;
// uni har bir o'zgarishda qayta yuborish behuda. Buning o'rniga har bir
// o'zgarish monoton `version` oladi, klient esa "menda N bor" deb
// so'raydi va faqat N dan keyingi o'zgarishlarni oladi.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"time"
)

// PublicKey — nodening doimiy Curve25519 kaliti.
type PublicKey [32]byte

// NodeID — public kalitdan hosil qilingan barqaror identifikator
// (ARCHITECTURE.md §3.1.2: node_id = SHA-256(pubkey)).
//
// Kalitdan hosil qilingani muhim: identifikatorni CP bermaydi, ya'ni
// uni soxtalashtirish uchun kalitning o'zi kerak.
func NodeID(key PublicKey) string {
	sum := sha256.Sum256(key[:])
	return hex.EncodeToString(sum[:])
}

// Node — ro'yxatdagi bitta qurilma.
type Node struct {
	ID        string
	PublicKey PublicKey

	// Tenant — izolyatsiya chegarasi. Node faqat o'z tenantidagi
	// peerlarni ko'radi.
	Tenant string

	// Hostname — foydalanuvchi uchun nom ("laptop", "db-01").
	Hostname string

	// Addresses — nodega tegishli prefikslar (IPAM bergan /128 va
	// subnet-router bo'lsa qo'shimchalari).
	//
	// Bu ro'yxat peer tomonda `allowed_ips` ga aylanadi, ya'ni u ham
	// marshrutlash jadvali, ham cryptokey routing ruxsat ro'yxati
	// bo'ladi (ARCHITECTURE.md §4.2).
	Addresses []netip.Prefix

	// Endpoints — nodening underlay manzillari: LAN, STUN topgan
	// public manzil va h.k.
	Endpoints []netip.AddrPort

	// Tags — mikrosegmentatsiya uchun ("tag:prod", "tag:db").
	Tags []string

	// RelayHome — nodega eng yaqin relay PoP identifikatori.
	RelayHome string

	CreatedAt time.Time
	LastSeen  time.Time

	// ExpiresAt — heartbeat kelmasa node shu vaqtdan keyin
	// ro'yxatdan chiqariladi.
	ExpiresAt time.Time
}

// Online — node hozir faol hisoblanadimi.
func (n *Node) Online(now time.Time) bool {
	return n.ExpiresAt.After(now)
}

// Clone chuqur nusxa qaytaradi.
//
// Registry tashqariga har doim nusxa beradi: chaqiruvchi qaytarilgan
// slice'ni o'zgartirsa ichki holat buzilmasligi kerak.
func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}

	copied := *n
	copied.Addresses = slices.Clone(n.Addresses)
	copied.Endpoints = slices.Clone(n.Endpoints)
	copied.Tags = slices.Clone(n.Tags)
	return &copied
}
