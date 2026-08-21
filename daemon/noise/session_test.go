package noise

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestSession_NonceIncrementsPerPacket(t *testing.T) {
	a, _, _, _ := establish(t)

	for want := range uint64(5) {
		packet, err := a.Seal(TypeData, []byte("x"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		header, err := ParseHeader(packet)
		if err != nil {
			t.Fatalf("ParseHeader: %v", err)
		}
		if header.Counter != want {
			t.Errorf("counter: %d kutilgan, %d olindi", want, header.Counter)
		}
	}
}

func TestSession_RejectsReplayedPacket(t *testing.T) {
	a, b, _, _ := establish(t)

	packet, err := a.Seal(TypeData, []byte("bir marta"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, _, err := b.Open(packet); err != nil {
		t.Fatalf("birinchi Open: %v", err)
	}

	// Aynan o'sha paket — AEAD baribir o'tadi, uni faqat replay oynasi
	// to'sadi.
	if _, _, err := b.Open(packet); !errors.Is(err, ErrReplay) {
		t.Fatalf("ErrReplay kutilgan edi, olindi: %v", err)
	}
}

// Tarmoqda qayta tartiblanish odatiy hol — sessiya uni qabul qilishi kerak.
func TestSession_AcceptsOutOfOrderDelivery(t *testing.T) {
	a, b, _, _ := establish(t)

	const count = 20
	packets := make([][]byte, count)
	for i := range packets {
		packet, err := a.Seal(TypeData, fmt.Appendf(nil, "paket-%d", i))
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		packets[i] = packet
	}

	// Teskari tartibda yetkazamiz.
	for i := count - 1; i >= 0; i-- {
		_, plaintext, err := b.Open(packets[i])
		if err != nil {
			t.Fatalf("teskari tartibda %d: %v", i, err)
		}
		if want := fmt.Sprintf("paket-%d", i); string(plaintext) != want {
			t.Errorf("%q kutilgan, %q olindi", want, plaintext)
		}
	}
}

func TestSession_RejectsTamperedCiphertext(t *testing.T) {
	a, b, _, _ := establish(t)

	packet, _ := a.Seal(TypeData, []byte("o'zgartirilmasin"))

	tampered := bytes.Clone(packet)
	tampered[len(tampered)-1] ^= 0x80

	if _, _, err := b.Open(tampered); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("ErrDecryptFailed kutilgan edi, olindi: %v", err)
	}
}

// Sarlavha AEAD uchun AD sifatida ishlatiladi — uni o'zgartirish ham
// deshifrlashni buzishi kerak.
func TestSession_HeaderIsAuthenticated(t *testing.T) {
	a, b, _, _ := establish(t)

	packet, _ := a.Seal(TypeData, []byte("yuk"))

	tampered := bytes.Clone(packet)
	tampered[0] = byte(TypeKeepalive) // turini o'zgartiramiz

	if _, _, err := b.Open(tampered); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("sarlavha o'zgarishi aniqlanmadi: %v", err)
	}
}

func TestSession_RejectsWrongIndex(t *testing.T) {
	a, b, _, _ := establish(t)

	packet, _ := a.Seal(TypeData, []byte("yuk"))

	tampered := bytes.Clone(packet)
	tampered[4] ^= 0xff // receiver_index

	_, _, err := b.Open(tampered)
	if !errors.Is(err, ErrIndexMismatch) {
		t.Fatalf("ErrIndexMismatch kutilgan edi, olindi: %v", err)
	}
}

// Uchinchi tomonning sessiyasi bizning paketimizni ocha olmasligi kerak.
func TestSession_ForeignSessionCannotDecrypt(t *testing.T) {
	a, _, _, _ := establish(t)
	_, other, _, _ := establish(t)

	packet, _ := a.Seal(TypeData, []byte("maxfiy"))

	if _, _, err := other.Open(packet); err == nil {
		t.Fatal("begona sessiya paketni ochdi")
	}
}

func TestSession_RekeyPolicy(t *testing.T) {
	a, _, _, _ := establish(t)

	if a.NeedsRekey() {
		t.Error("yangi sessiya rekey talab qilmasligi kerak")
	}
	if a.Expired() {
		t.Error("yangi sessiya muddati o'tgan bo'lmasligi kerak")
	}

	// Paket soni bo'yicha chegara.
	a.sendMu.Lock()
	a.nonce = RekeyAfterMessages
	a.sendMu.Unlock()

	if !a.NeedsRekey() {
		t.Error("paket chegarasidan keyin rekey kerak")
	}
}

func TestSession_ExpiredRejectsBothDirections(t *testing.T) {
	a, b, _, _ := establish(t)

	packet, _ := a.Seal(TypeData, []byte("yuk"))

	// Sessiyani eskirgan qilib ko'rsatamiz.
	a.created = a.created.Add(-RejectAfterTime - 1)
	b.created = b.created.Add(-RejectAfterTime - 1)

	if _, err := a.Seal(TypeData, []byte("yuk")); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("Seal: ErrSessionExpired kutilgan, olindi: %v", err)
	}
	if _, _, err := b.Open(packet); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("Open: ErrSessionExpired kutilgan, olindi: %v", err)
	}
}

func TestSession_NonceExhaustionIsRefused(t *testing.T) {
	a, _, _, _ := establish(t)

	a.sendMu.Lock()
	a.nonce = ^uint64(0) - 1
	a.sendMu.Unlock()

	if _, err := a.Seal(TypeData, []byte("yuk")); !errors.Is(err, ErrNonceExhausted) {
		t.Fatalf("ErrNonceExhausted kutilgan edi, olindi: %v", err)
	}
}

func TestSession_KeepaliveRoundTrip(t *testing.T) {
	a, b, _, _ := establish(t)

	packet, err := a.Seal(TypeKeepalive, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	header, plaintext, err := b.Open(packet)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if header.Type != TypeKeepalive {
		t.Errorf("tur: %s olindi", header.Type)
	}
	if len(plaintext) != 0 {
		t.Errorf("keepalive bo'sh bo'lishi kerak, %d bayt olindi", len(plaintext))
	}
}

// Session bir nechta goroutine'dan ishlatiladi (TUN o'quvchisi va UDP
// o'quvchisi alohida). Nonce takrorlanmasligi SHART — takrorlansa
// ChaCha20-Poly1305 butunlay buziladi.
func TestSession_ConcurrentSealProducesUniqueNonces(t *testing.T) {
	a, _, _, _ := establish(t)

	const workers, perWorker = 8, 200

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[uint64]bool, workers*perWorker)

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				packet, err := a.Seal(TypeData, []byte("parallel"))
				if err != nil {
					t.Errorf("Seal: %v", err)
					return
				}
				header, err := ParseHeader(packet)
				if err != nil {
					t.Errorf("ParseHeader: %v", err)
					return
				}

				mu.Lock()
				if seen[header.Counter] {
					t.Errorf("nonce %d takrorlandi", header.Counter)
				}
				seen[header.Counter] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != workers*perWorker {
		t.Errorf("%d ta noyob nonce kutilgan, %d olindi", workers*perWorker, len(seen))
	}
}

func TestParseHeader_RejectsBadInput(t *testing.T) {
	if _, err := ParseHeader(nil); !errors.Is(err, ErrShortPacket) {
		t.Errorf("bo'sh paket: %v", err)
	}
	if _, err := ParseHeader(make([]byte, HeaderSize-1)); !errors.Is(err, ErrShortPacket) {
		t.Errorf("qisqa paket: %v", err)
	}

	unknown := make([]byte, HeaderSize)
	unknown[0] = 0x7f
	if _, err := ParseHeader(unknown); !errors.Is(err, ErrUnknownType) {
		t.Errorf("noma'lum tur: %v", err)
	}
}

func TestHeader_MarshalRoundTrip(t *testing.T) {
	want := Header{Type: TypeData, ReceiverIndex: 0xdeadbeef, Counter: 1 << 40}

	buf := make([]byte, HeaderSize)
	if _, err := want.MarshalTo(buf); err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}

	got, err := ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got != want {
		t.Errorf("%+v kutilgan, %+v olindi", want, got)
	}

	if _, err := want.MarshalTo(make([]byte, HeaderSize-1)); !errors.Is(err, ErrBufferTooSmall) {
		t.Errorf("kichik bufer: %v", err)
	}
}

func BenchmarkSession_SealOpen(b *testing.B) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()

	hsA, _ := StartInitiator(alice, bob.PublicKey())
	hsB, _ := StartResponder(bob)
	initiation, _ := hsA.WriteInitiation()
	_ = hsB.ReadInitiation(initiation)
	response, sessionB, _ := hsB.WriteResponse()
	sessionA, _ := hsA.ReadResponse(response)

	payload := make([]byte, 1280) // TUN MTU

	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		packet, err := sessionA.Seal(TypeData, payload)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := sessionB.Open(packet); err != nil {
			b.Fatal(err)
		}
	}
}
