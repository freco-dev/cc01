package noise

import "golang.org/x/crypto/curve25519"

// curve25519Public private kalitdan public kalitni hisoblaydi.
func curve25519Public(private []byte) []byte {
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		// X25519 faqat noto'g'ri uzunlikda xato beradi, uni chaqiruvchi
		// allaqachon tekshirgan.
		panic("noise: curve25519: " + err.Error())
	}
	return public
}
