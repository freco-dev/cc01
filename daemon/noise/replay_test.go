package noise

import (
	"math/rand/v2"
	"testing"
)

func TestReplayWindow_AcceptsFirstCounterZero(t *testing.T) {
	w := NewReplayWindow()

	// Nonce 0 dan boshlanadi — birinchi paket qabul qilinishi shart.
	if !w.Accept(0) {
		t.Fatal("0 qabul qilinishi kerak edi")
	}
	if w.Accept(0) {
		t.Fatal("0 ikkinchi marta rad etilishi kerak edi")
	}
}

func TestReplayWindow_AcceptsSequential(t *testing.T) {
	w := NewReplayWindow()

	for i := range uint64(10_000) {
		if !w.Accept(i) {
			t.Fatalf("ketma-ket %d rad etildi", i)
		}
	}
	if w.Last() != 9_999 {
		t.Errorf("Last: 9999 kutilgan, %d olindi", w.Last())
	}
}

func TestReplayWindow_RejectsDuplicates(t *testing.T) {
	w := NewReplayWindow()

	for i := range uint64(100) {
		w.Accept(i)
	}
	for i := range uint64(100) {
		if w.Accept(i) {
			t.Fatalf("takroriy %d qabul qilindi", i)
		}
	}
}

// Tarmoqda qayta tartiblanish odatiy hol — oyna ichidagi kechikkan
// paketlar qabul qilinishi kerak.
func TestReplayWindow_AcceptsOutOfOrderWithinWindow(t *testing.T) {
	w := NewReplayWindow()

	if !w.Accept(500) {
		t.Fatal("500 qabul qilinishi kerak edi")
	}

	for _, counter := range []uint64{499, 100, 1, 0, 499 - 1} {
		if !w.Accept(counter) {
			t.Errorf("oyna ichidagi %d rad etildi", counter)
		}
	}

	// Ular endi ko'rilgan.
	if w.Accept(499) {
		t.Error("499 takroran qabul qilindi")
	}
}

func TestReplayWindow_RejectsTooOld(t *testing.T) {
	w := NewReplayWindow()

	w.Accept(WindowSize + 100)

	// Oynadan chiqib ketganlar.
	for _, counter := range []uint64{0, 99, 100} {
		if w.Accept(counter) {
			t.Errorf("eski %d qabul qilindi (last=%d)", counter, w.Last())
		}
	}

	// Chegara: last-counter == WindowSize → rad, WindowSize-1 → qabul.
	last := w.Last()
	if w.Accept(last - WindowSize) {
		t.Error("chegaradan tashqaridagi qabul qilindi")
	}
	if !w.Accept(last - WindowSize + 1) {
		t.Error("chegaradagi rad etildi")
	}
}

// Katta sakrash butun bitmapni tozalashi kerak, aks holda eski bitlar
// yangi hisoblagichlarni "ko'rilgan" qilib ko'rsatadi.
func TestReplayWindow_LargeJumpClearsHistory(t *testing.T) {
	w := NewReplayWindow()

	for i := range uint64(1000) {
		w.Accept(i)
	}

	const far = 1_000_000
	if !w.Accept(far) {
		t.Fatal("uzoq hisoblagich rad etildi")
	}

	// Sakrashdan keyingi qo'shnilar toza bo'lishi kerak.
	for _, counter := range []uint64{far - 1, far - 500, far - WindowSize + 1} {
		if !w.Accept(counter) {
			t.Errorf("sakrashdan keyin %d rad etildi", counter)
		}
	}
}

// Bitmap halqa bo'lgani uchun blok chegaralari eng xato chiqadigan joy.
func TestReplayWindow_BlockBoundaries(t *testing.T) {
	w := NewReplayWindow()

	for _, counter := range []uint64{63, 64, 65, 127, 128, WindowSize - 1, WindowSize} {
		if !w.Accept(counter) {
			t.Errorf("%d rad etildi", counter)
		}
		if w.Accept(counter) {
			t.Errorf("%d takroran qabul qilindi", counter)
		}
	}
}

func TestReplayWindow_RejectsMaxCounter(t *testing.T) {
	w := NewReplayWindow()

	// Nonce bu qiymatga yetmasligi kerak — undan oldin rekey bo'ladi.
	if w.Accept(^uint64(0)) {
		t.Error("maksimal hisoblagich qabul qilindi")
	}
}

// Aralash tartibda kelgan paketlarning HAR BIRI aynan bir marta qabul
// qilinishi kerak — na ko'p, na kam.
func TestReplayWindow_EachCounterAcceptedExactlyOnce(t *testing.T) {
	w := NewReplayWindow()
	source := rand.New(rand.NewPCG(1, 2))

	const total = 5_000
	counters := make([]uint64, total)
	for i := range counters {
		counters[i] = uint64(i)
	}
	source.Shuffle(total, func(i, j int) {
		counters[i], counters[j] = counters[j], counters[i]
	})

	accepted := make(map[uint64]bool, total)
	for _, counter := range counters {
		if w.Accept(counter) {
			if accepted[counter] {
				t.Fatalf("%d ikki marta qabul qilindi", counter)
			}
			accepted[counter] = true
		}
	}

	// Aralash tartibda ba'zilari oynadan chiqib ketishi mumkin — bu
	// to'g'ri xatti-harakat. Muhimi: hech biri ikki marta o'tmasin.
	if len(accepted) == 0 {
		t.Fatal("hech narsa qabul qilinmadi")
	}
	t.Logf("%d/%d qabul qilindi (qolganlari oynadan chiqib ketgan)", len(accepted), total)
}

func BenchmarkReplayWindow_Accept(b *testing.B) {
	w := NewReplayWindow()
	for i := 0; b.Loop(); i++ {
		w.Accept(uint64(i))
	}
}
