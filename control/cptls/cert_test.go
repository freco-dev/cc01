package cptls

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
)

// testSPKI / testPin — `daemon/control` dagi nusxasi bilan AYNAN bir
// xil vektor.
//
// Pin formati ikki modulda alohida yozilgan (ular bir-birini import
// qilmaydi: klient serverning moduliga bog'lanmasligi kerak). Formatlar
// ajralib ketsa nodelar CP ga umuman ulana olmaydi va sabab
// tushunarsiz bo'lardi — shuning uchun ikkala tomonda ham bir xil
// vektor qulflangan.
var testSPKI = []byte{
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
	0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
}

const testPin = "sha256/Abq+GQYSpO6sMRzgUlRI1WT9TUTqQTt2VDx9zRck39Y="

func TestPin_MatchesSharedVector(t *testing.T) {
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: testSPKI}

	if got := Pin(cert); got != testPin {
		t.Fatalf("pin formati o'zgardi:\n  olindi:   %s\n  kutilgan: %s\n"+
			"  daemon/control/pin_test.go dagi nusxa bilan solishtiring", got, testPin)
	}
}

func TestGenerateSelfSigned_UsableForTLS13(t *testing.T) {
	cert, err := GenerateSelfSigned([]string{"cp.example", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	if cert.Leaf == nil {
		t.Fatal("Leaf to'ldirilmagan — har ulanishda qayta parse qilinardi")
	}

	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "cp.example" {
		t.Errorf("DNS nomlari: %v", cert.Leaf.DNSNames)
	}
	if len(cert.Leaf.IPAddresses) != 2 {
		t.Errorf("IP manzillar: %v", cert.Leaf.IPAddresses)
	}

	cfg := ServerConfig(cert)
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("TLS 1.3 talab qilinishi kerak, olindi: %#x", cfg.MinVersion)
	}
}

// Har bir yaratilgan sertifikat o'z kalitiga ega bo'lishi kerak.
func TestGenerateSelfSigned_KeysAreDistinct(t *testing.T) {
	first, err := GenerateSelfSigned(nil)
	if err != nil {
		t.Fatalf("birinchi: %v", err)
	}
	second, err := GenerateSelfSigned(nil)
	if err != nil {
		t.Fatalf("ikkinchi: %v", err)
	}

	if Pin(first.Leaf) == Pin(second.Leaf) {
		t.Fatal("ikkita sertifikat bir xil kalit oldi")
	}
}

func TestEncode_ProducesPEM(t *testing.T) {
	cert, err := GenerateSelfSigned([]string{"cp.example"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	certPEM, keyPEM, err := Encode(cert)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if !strings.HasPrefix(string(certPEM), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("sertifikat PEM emas: %.40s", certPEM)
	}
	if !strings.HasPrefix(string(keyPEM), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("kalit PEM emas: %.40s", keyPEM)
	}

	// Qayta yuklab bo'lishi kerak — saqlash yo'li shu orqali ishlaydi.
	reloaded, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("qayta yuklash: %v", err)
	}
	if len(reloaded.Certificate) == 0 {
		t.Fatal("qayta yuklangan sertifikat bo'sh")
	}
}
