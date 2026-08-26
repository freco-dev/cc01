package noise

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/flynn/noise"
)

// KeySize — Curve25519 kalit uzunligi.
const KeySize = 32

// PublicKey — nodening doimiy public kaliti. U node identifikatori:
// ARCHITECTURE.md §3.1.2 bo'yicha node_id = SHA-256(pubkey).
type PublicKey [KeySize]byte

func (k PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// Bytes — kalitning xom ko'rinishi (nusxa emas, massiv bo'lagi).
func (k PublicKey) Bytes() []byte { return k[:] }

// IsZero — kalit o'rnatilmaganmi.
func (k PublicKey) IsZero() bool {
	var zero PublicKey
	return subtle.ConstantTimeCompare(k[:], zero[:]) == 1
}

func ParsePublicKey(encoded string) (PublicKey, error) {
	var key PublicKey

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return key, fmt.Errorf("noise: public kalitni dekodlash: %w", err)
	}
	if len(raw) != KeySize {
		return key, fmt.Errorf("noise: public kalit uzunligi %d, kutilgan %d", len(raw), KeySize)
	}

	copy(key[:], raw)
	return key, nil
}

// Identity — nodening doimiy kalit jufti.
//
// Private kalit qurilmadan HECH QACHON chiqmaydi (ARCHITECTURE.md §3.1.1).
// Bu tur uni String() da ham, xato matnlarida ham oshkor qilmaydi.
type Identity struct {
	pair noise.DHKey
}

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// GenerateIdentity yangi kalit jufti yaratadi.
func GenerateIdentity() (*Identity, error) {
	pair, err := cipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("noise: kalit yaratish: %w", err)
	}
	return &Identity{pair: pair}, nil
}

// IdentityFromPrivate mavjud private kalitdan identity tiklaydi.
func IdentityFromPrivate(private []byte) (*Identity, error) {
	if len(private) != KeySize {
		return nil, fmt.Errorf("noise: private kalit uzunligi %d, kutilgan %d", len(private), KeySize)
	}

	pair, err := noise.DH25519.GenerateKeypair(zeroReader{})
	if err != nil {
		return nil, err
	}

	copy(pair.Private, private)
	pair.Public = curve25519Public(private)

	return &Identity{pair: pair}, nil
}

// PublicKey — identityning public qismi.
func (id *Identity) PublicKey() PublicKey {
	var key PublicKey
	copy(key[:], id.pair.Public)
	return key
}

// MarshalPrivateKey private kalitni saqlash uchun chiqaradi.
//
// ⚠️ Bu yagona joy — boshqa hech qayerda private kalit tashqariga
// chiqmaydi. Natija diskka faqat shifrlangan holda yoki TPM/Keychain
// ichida saqlanishi kerak (DEV_SPEC §7.2 S-1), log'ga esa hech qachon.
func (id *Identity) MarshalPrivateKey() []byte {
	out := make([]byte, KeySize)
	copy(out, id.pair.Private)
	return out
}

// String private kalitni HECH QACHON ko'rsatmaydi.
func (id *Identity) String() string {
	return "noise.Identity(" + id.PublicKey().String() + ")"
}

// zeroReader — GenerateKeypair ga beriladigan qo'g'irchoq: hosil bo'lgan
// kalit baribir darhol almashtiriladi.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
