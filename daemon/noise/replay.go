package noise

// ReplayWindow — takroriy va juda eski paketlarni rad etuvchi sirpanuvchi
// oyna (RFC 6479 algoritmi, WireGuard ham shuni ishlatadi).
//
// Nima uchun kerak: AEAD paketning o'zgartirilmaganini isbotlaydi, lekin
// TAKRORLANMAGANINI emas. Tajovuzkor ushlab qolgan paketni qayta yuborsa,
// u kriptografik jihatdan haqiqiy bo'lib qolaveradi. Oyna har bir
// hisoblagichni faqat bir marta qabul qiladi.
//
// Tuzilishi: bitmap bloklar halqasi. Ketma-ket kelmagan paketlar ham
// qabul qilinadi (tarmoqda qayta tartiblanish odatiy hol), lekin oynadan
// tashqarida qolganlari — yo'q.
type ReplayWindow struct {
	bitmap [blockCount]uint64
	last   uint64
}

const (
	blockBits  = 64
	blockCount = WindowSize / blockBits

	// WindowSize — necha paketlik tarixni eslab qolamiz.
	// 2048 bit ≈ 2048 paket: tarmoqdagi har qanday oqilona qayta
	// tartiblanishdan ancha katta, lekin atigi 256 bayt xotira.
	WindowSize = 2048
)

// NewReplayWindow bo'sh oyna qaytaradi.
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

// Accept hisoblagichni tekshiradi va qabul qilinsa uni ko'rilgan deb
// belgilaydi. Rad etilsa holat o'zgarmaydi.
//
// Bu metod paket AEAD tekshiruvidan O'TGANDAN KEYIN chaqirilishi shart.
// Aks holda tajovuzkor soxta hisoblagichlar yuborib oynani oldinga
// surib yuborishi va haqiqiy paketlarni "eski" qilib qo'yishi mumkin.
func (w *ReplayWindow) Accept(counter uint64) bool {
	// Nonce hech qachon maksimal qiymatga yetmasligi kerak — sessiya
	// undan ancha oldin rekey qilinadi. Yetgan bo'lsa — bu bug yoki hujum.
	if counter == ^uint64(0) {
		return false
	}

	if counter > w.last {
		w.advance(counter)
		w.set(counter)
		w.last = counter
		return true
	}

	// Oynadan chiqib ketgan: juda eski.
	if w.last-counter >= WindowSize {
		return false
	}

	if w.isSet(counter) {
		return false
	}

	w.set(counter)
	return true
}

// advance oynani oldinga suradi va yangi ochilgan bitlarni tozalaydi.
func (w *ReplayWindow) advance(counter uint64) {
	lastBlock := w.last / blockBits
	nextBlock := counter / blockBits

	if nextBlock-lastBlock >= blockCount {
		// Sakrash oynadan katta — hamma narsani tozalaymiz.
		w.bitmap = [blockCount]uint64{}
		return
	}

	for block := lastBlock + 1; block <= nextBlock; block++ {
		w.bitmap[block%blockCount] = 0
	}
}

func (w *ReplayWindow) set(counter uint64) {
	block := (counter / blockBits) % blockCount
	w.bitmap[block] |= 1 << (counter % blockBits)
}

func (w *ReplayWindow) isSet(counter uint64) bool {
	block := (counter / blockBits) % blockCount
	return w.bitmap[block]&(1<<(counter%blockBits)) != 0
}

// Last — hozirgacha ko'rilgan eng katta hisoblagich.
func (w *ReplayWindow) Last() uint64 { return w.last }
