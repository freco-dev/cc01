package control

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

// testSPKI — sobit ochiq kalit ma'lumoti (Ed25519 SPKI, DER).
//
// Bu vektor `control/cptls` dagi nusxasi bilan BIR XIL bo'lishi
// shart: pin formati ikki modulda alohida yozilgan va ular ajralib
// ketsa nodelar CP ga ulana olmay qoladi.
var testSPKI = []byte{
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
	0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
}

// testPin — yuqoridagi SPKI uchun kutilgan pin.
const testPin = "sha256/Abq+GQYSpO6sMRzgUlRI1WT9TUTqQTt2VDx9zRck39Y="

func TestSPKIPin_MatchesSharedVector(t *testing.T) {
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: testSPKI}

	if got := SPKIPin(cert); got != testPin {
		t.Fatalf("pin formati o'zgardi:\n  olindi:   %s\n  kutilgan: %s\n"+
			"  control/cptls dagi nusxa bilan solishtiring", got, testPin)
	}
}

func TestVerifyPin_AcceptsMatchingPin(t *testing.T) {
	cert, raw := selfSigned(t)

	if err := verifyPin([][]byte{raw}, []string{SPKIPin(cert)}); err != nil {
		t.Fatalf("to'g'ri pin rad etildi: %v", err)
	}
}

// Kalit almashtirish paytida eski va yangi pin bir vaqtda amal qiladi.
func TestVerifyPin_AcceptsAnyOfSeveral(t *testing.T) {
	cert, raw := selfSigned(t)

	pins := []string{"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", SPKIPin(cert)}
	if err := verifyPin([][]byte{raw}, pins); err != nil {
		t.Fatalf("ro'yxatdagi pin rad etildi: %v", err)
	}
}

// Asosiy xavfsizlik xossasi: boshqa kalitli sertifikat o'tmasligi kerak.
func TestVerifyPin_RejectsDifferentKey(t *testing.T) {
	_, raw := selfSigned(t)
	other, _ := selfSigned(t)

	err := verifyPin([][]byte{raw}, []string{SPKIPin(other)})
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("boshqa kalit qabul qilindi: %v", err)
	}

	// Xato ikkala pinni ham ko'rsatishi kerak — aks holda operator
	// nima nimaga mos kelmaganini bilmaydi.
	if !strings.Contains(err.Error(), "kutilgan") || !strings.Contains(err.Error(), "olingan") {
		t.Errorf("xato tushuntirmaydi: %v", err)
	}
}

func TestVerifyPin_RejectsEmptyChain(t *testing.T) {
	if err := verifyPin(nil, []string{testPin}); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("bo'sh zanjir qabul qilindi: %v", err)
	}
}

// Pin berilganda standart zanjir tekshiruvi o'rniga pin qo'yiladi.
func TestTLSConfig_PinReplacesChainVerification(t *testing.T) {
	cfg := tlsConfig("cp.example", []string{testPin})

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("TLS 1.3 talab qilinishi kerak, olindi: %#x", cfg.MinVersion)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Error("pin tekshiruvi ulanmagan")
	}

	// Pin yo'q bo'lsa standart tekshiruv qoladi.
	plain := tlsConfig("cp.example", nil)
	if plain.InsecureSkipVerify {
		t.Error("pinsiz holatda zanjir tekshiruvi o'chirilgan")
	}
}

func selfSigned(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()

	cert := generateForTest(t)
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("sertifikatni o'qish: %v", err)
	}
	return parsed, cert.Certificate[0]
}
