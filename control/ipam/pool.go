package ipam

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
)

var (
	// ErrPoolExhausted — ota-prefiksda bo'sh joy qolmadi.
	ErrPoolExhausted = errors.New("ipam: prefikslar tugadi")

	// ErrNotContained — so'ralgan prefiks ota-prefiks ichida emas.
	ErrNotContained = errors.New("ipam: prefiks ota-prefiks ichida emas")

	// ErrBadPrefixLen — bola prefiks uzunligi noto'g'ri.
	ErrBadPrefixLen = errors.New("ipam: prefiks uzunligi noto'g'ri")
)

// scanThreshold — bo'sh prefiksni qidirish strategiyasini tanlash
// chegarasi.
//
// Kichik makonlarda (masalan /48 ichidagi /64 lar — 65536 ta) ketma-ket
// skanerlash aniq va tez. Katta makonlarda (/64 ichidagi /128 lar —
// 2^64 ta) skanerlash mumkin emas: u yerda tasodifiy tanlab, band
// bo'lsa qayta urinamiz. To'qnashuv ehtimoli amalda nolga teng.
const scanThreshold = 1 << 20

// allocatePrefix ota-prefiks ichidan bo'sh bola prefiksni tanlaydi.
//
// `taken` — band prefikslar; `preferred` bo'sh bo'lmasa va bo'sh
// bo'lsa, aynan o'sha qaytariladi (sticky taqsimlash).
func allocatePrefix(
	parent netip.Prefix,
	childBits int,
	taken map[netip.Prefix]struct{},
	preferred netip.Prefix,
) (netip.Prefix, error) {
	if err := validateChild(parent, childBits); err != nil {
		return netip.Prefix{}, err
	}

	// Sticky: node qayta ulanganda o'sha manzilni qaytarib olishi
	// IP o'zgarishini minimallashtiradi (ARCHITECTURE.md §3.1.3).
	if preferred.IsValid() {
		if err := checkPreferred(parent, childBits, preferred); err == nil {
			if _, busy := taken[preferred]; !busy {
				return preferred, nil
			}
		}
	}

	span := childBits - parent.Bits()
	if span < 63 && int64(1)<<span <= scanThreshold {
		return scanForFree(parent, childBits, taken, int64(1)<<span)
	}
	return randomFree(parent, childBits, taken)
}

func validateChild(parent netip.Prefix, childBits int) error {
	if !parent.IsValid() {
		return fmt.Errorf("%w: ota-prefiks yaroqsiz", ErrBadPrefixLen)
	}
	if !parent.Addr().Is6() || parent.Addr().Is4In6() {
		return fmt.Errorf("ipam: faqat IPv6: %v", parent)
	}
	if childBits <= parent.Bits() || childBits > 128 {
		return fmt.Errorf("%w: /%d ota-prefiks /%d ichida bo'la olmaydi",
			ErrBadPrefixLen, childBits, parent.Bits())
	}
	return nil
}

func checkPreferred(parent netip.Prefix, childBits int, preferred netip.Prefix) error {
	if preferred.Bits() != childBits {
		return ErrBadPrefixLen
	}
	if !parent.Contains(preferred.Addr()) {
		return ErrNotContained
	}
	if preferred.Masked() != preferred {
		return fmt.Errorf("ipam: prefiks normallashtirilmagan: %v", preferred)
	}
	return nil
}

// scanForFree kichik makonlarda birinchi bo'sh prefiksni topadi.
func scanForFree(
	parent netip.Prefix,
	childBits int,
	taken map[netip.Prefix]struct{},
	total int64,
) (netip.Prefix, error) {
	parentRaw := parent.Addr().As16()
	base := new(big.Int).SetBytes(parentRaw[:])
	step := new(big.Int).Lsh(big.NewInt(1), uint(128-childBits))

	candidate := new(big.Int)
	offset := new(big.Int)

	for index := range total {
		offset.Mul(big.NewInt(index), step)
		candidate.Add(base, offset)

		prefix := netip.PrefixFrom(addrFromBig(candidate), childBits)
		if _, busy := taken[prefix]; !busy {
			return prefix, nil
		}
	}

	return netip.Prefix{}, fmt.Errorf("%w: %v ichida /%d", ErrPoolExhausted, parent, childBits)
}

// randomFree katta makonlarda tasodifiy bo'sh prefiks tanlaydi.
//
// Nega tasodifiy: /64 ichida 2^64 ta /128 bor — ularni ro'yxatlash
// mumkin emas. Tasodifiy tanlash bir tekis taqsimlaydi va band
// manzillar sonini oshkor qilmaydi.
func randomFree(
	parent netip.Prefix,
	childBits int,
	taken map[netip.Prefix]struct{},
) (netip.Prefix, error) {
	hostBits := 128 - childBits
	parentRaw := parent.Addr().As16()
	base := new(big.Int).SetBytes(parentRaw[:])

	// Ota-prefiksdan tashqariga chiqmaslik uchun tasodifiy qism
	// faqat bola bitlarini egallaydi.
	spanBits := childBits - parent.Bits()
	limit := new(big.Int).Lsh(big.NewInt(1), uint(spanBits))

	const attempts = 32
	for range attempts {
		offset, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("ipam: tasodifiy qiymat: %w", err)
		}

		offset.Lsh(offset, uint(hostBits))
		candidate := new(big.Int).Add(base, offset)

		prefix := netip.PrefixFrom(addrFromBig(candidate), childBits)
		if _, busy := taken[prefix]; !busy {
			return prefix, nil
		}
	}

	// 32 marta ketma-ket to'qnashuv — bu makon deyarli to'lganini
	// bildiradi (yoki juda kichik ekanini).
	return netip.Prefix{}, fmt.Errorf("%w: %v ichida /%d (%d urinishdan keyin)",
		ErrPoolExhausted, parent, childBits, attempts)
}

// addrFromBig 128-bitli sonni IPv6 manziliga aylantiradi.
func addrFromBig(value *big.Int) netip.Addr {
	var raw [16]byte
	value.FillBytes(raw[:])
	return netip.AddrFrom16(raw)
}
