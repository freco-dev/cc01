package noise

import (
	"bytes"
	"errors"
	"testing"
)

// establish to'liq handshake bajaradi va ikkala tomon sessiyasini qaytaradi.
func establish(t *testing.T) (initiator, responder *Session, alice, bob *Identity) {
	t.Helper()

	alice, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err = GenerateIdentity()
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	// IK: initiator responderning public kalitini OLDINDAN biladi.
	hsA, err := StartInitiator(alice, bob.PublicKey())
	if err != nil {
		t.Fatalf("StartInitiator: %v", err)
	}
	hsB, err := StartResponder(bob)
	if err != nil {
		t.Fatalf("StartResponder: %v", err)
	}

	initiation, err := hsA.WriteInitiation()
	if err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	if err := hsB.ReadInitiation(initiation); err != nil {
		t.Fatalf("ReadInitiation: %v", err)
	}

	response, sessionB, err := hsB.WriteResponse()
	if err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	sessionA, err := hsA.ReadResponse(response)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	return sessionA, sessionB, alice, bob
}

func TestHandshake_EstablishesSessionsBothWays(t *testing.T) {
	a, b, alice, bob := establish(t)

	// Har bir tomon boshqasining statik kalitini bilishi kerak.
	if a.Peer() != bob.PublicKey() {
		t.Errorf("initiator peer: %s kutilgan, %s olindi", bob.PublicKey(), a.Peer())
	}
	if b.Peer() != alice.PublicKey() {
		t.Errorf("responder peer: %s kutilgan, %s olindi", alice.PublicKey(), b.Peer())
	}

	// Indekslar bir-biriga mos kelishi shart, aks holda paketlar
	// noto'g'ri sessiyaga tushadi.
	if a.LocalIndex() != b.RemoteIndex() {
		t.Errorf("indeks: A.local=%d != B.remote=%d", a.LocalIndex(), b.RemoteIndex())
	}
	if b.LocalIndex() != a.RemoteIndex() {
		t.Errorf("indeks: B.local=%d != A.remote=%d", b.LocalIndex(), a.RemoteIndex())
	}

	if !a.IsInitiator() {
		t.Error("A initiator bo'lishi kerak")
	}
	if b.IsInitiator() {
		t.Error("B initiator bo'lmasligi kerak")
	}
}

func TestHandshake_EncryptedEchoWorks(t *testing.T) {
	a, b, _, _ := establish(t)

	message := []byte("cc01 mesh: birinchi shifrlangan paket")

	packet, err := a.Seal(TypeData, message)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(packet, message) {
		t.Fatal("ochiq matn paketda ko'rinib turibdi")
	}

	_, plaintext, err := b.Open(packet)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(plaintext, message) {
		t.Errorf("%q kutilgan, %q olindi", message, plaintext)
	}

	// Teskari yo'nalish ham ishlashi kerak.
	reply, err := b.Seal(TypeData, []byte("javob"))
	if err != nil {
		t.Fatalf("Seal (B): %v", err)
	}
	_, got, err := a.Open(reply)
	if err != nil {
		t.Fatalf("Open (A): %v", err)
	}
	if string(got) != "javob" {
		t.Errorf("javob: %q olindi", got)
	}
}

// IK'da initiator responderning kalitini biladi. Noto'g'ri kalit bilan
// urinish responder tomonda muvaffaqiyatsiz bo'lishi kerak — bu MITM'ga
// qarshi asosiy himoya.
func TestHandshake_WrongResponderKeyFails(t *testing.T) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()
	impostor, _ := GenerateIdentity()

	// Alice o'zini Bob bilan gaplashyapman deb o'ylaydi, lekin impostorning
	// kalitini ishlatadi.
	hsA, err := StartInitiator(alice, impostor.PublicKey())
	if err != nil {
		t.Fatalf("StartInitiator: %v", err)
	}
	hsB, _ := StartResponder(bob)

	initiation, err := hsA.WriteInitiation()
	if err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}

	err = hsB.ReadInitiation(initiation)
	if !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("ErrHandshakeFailed kutilgan edi, olindi: %v", err)
	}
}

func TestHandshake_TamperedInitiationFails(t *testing.T) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()

	hsA, _ := StartInitiator(alice, bob.PublicKey())
	hsB, _ := StartResponder(bob)

	initiation, _ := hsA.WriteInitiation()

	// Shifrlangan qismdagi bitta bitni o'zgartiramiz.
	tampered := bytes.Clone(initiation)
	tampered[len(tampered)-1] ^= 0x01

	if err := hsB.ReadInitiation(tampered); !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("ErrHandshakeFailed kutilgan edi, olindi: %v", err)
	}
}

// Javob boshqa handshake'ga tegishli bo'lsa rad etilishi kerak.
func TestHandshake_ResponseForDifferentSessionRejected(t *testing.T) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()

	hsA, _ := StartInitiator(alice, bob.PublicKey())
	hsB, _ := StartResponder(bob)

	initiation, _ := hsA.WriteInitiation()
	_ = hsB.ReadInitiation(initiation)
	response, _, _ := hsB.WriteResponse()

	// Boshqa initiator o'sha javobni qabul qilishga urinadi.
	other, _ := GenerateIdentity()
	hsOther, _ := StartInitiator(other, bob.PublicKey())

	if _, err := hsOther.ReadResponse(response); err == nil {
		t.Fatal("begona javob qabul qilindi")
	}
}

func TestHandshake_RoleGuards(t *testing.T) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()

	hsA, _ := StartInitiator(alice, bob.PublicKey())
	hsB, _ := StartResponder(bob)

	if _, _, err := hsA.WriteResponse(); err == nil {
		t.Error("initiator WriteResponse chaqira olmasligi kerak")
	}
	if _, err := hsB.WriteInitiation(); err == nil {
		t.Error("responder WriteInitiation chaqira olmasligi kerak")
	}
	if err := hsA.ReadInitiation(nil); err == nil {
		t.Error("initiator ReadInitiation chaqira olmasligi kerak")
	}
	if _, err := hsB.ReadResponse(nil); err == nil {
		t.Error("responder ReadResponse chaqira olmasligi kerak")
	}
}

func TestHandshake_RequiresPeerKey(t *testing.T) {
	alice, _ := GenerateIdentity()

	if _, err := StartInitiator(alice, PublicKey{}); err == nil {
		t.Fatal("bo'sh peer kaliti bilan handshake boshlanmasligi kerak")
	}
}

// Har bir handshake yangi kalitlar beradi (PFS). Ikki marta bir xil
// juftlik orasidagi sessiya kalitlari boshqa bo'lishi shart.
func TestHandshake_ForwardSecrecyDifferentKeysEachTime(t *testing.T) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()

	seal := func() []byte {
		hsA, _ := StartInitiator(alice, bob.PublicKey())
		hsB, _ := StartResponder(bob)

		initiation, _ := hsA.WriteInitiation()
		_ = hsB.ReadInitiation(initiation)
		response, _, _ := hsB.WriteResponse()
		session, err := hsA.ReadResponse(response)
		if err != nil {
			t.Fatalf("ReadResponse: %v", err)
		}

		packet, err := session.Seal(TypeData, []byte("bir xil matn"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		return packet
	}

	first, second := seal(), seal()

	// Sarlavhadan keyingi shifrlangan qism bir xil bo'lmasligi kerak.
	if bytes.Equal(first[HeaderSize:], second[HeaderSize:]) {
		t.Fatal("ikki sessiyada bir xil shifr matn — ephemeral kalitlar ishlamayapti")
	}
}

func TestIdentity_PublicKeyRoundTrip(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	parsed, err := ParsePublicKey(id.PublicKey().String())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if parsed != id.PublicKey() {
		t.Error("public kalit round-trip'da o'zgardi")
	}
}

// Private kalit hech qanday matnli ko'rinishda oshkor bo'lmasligi kerak.
func TestIdentity_StringDoesNotLeakPrivateKey(t *testing.T) {
	id, _ := GenerateIdentity()

	text := id.String()
	if !bytes.Contains([]byte(text), []byte(id.PublicKey().String())) {
		t.Error("String() public kalitni ko'rsatishi kerak")
	}
	if len(text) > 128 {
		t.Errorf("String() juda uzun — private kalit ham chiqib ketgan bo'lishi mumkin: %q", text)
	}
}
