package tlsmgr

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/mholt/acmez/v3"
)

// ACME haqiqiy chiqarish sinovlari bu yerda YO'Q: ular tashqi ACME
// serverini va haqiqiy domenni talab qiladi. Bu yerda sozlash va
// ulanish tekshiriladi — aynan shu joylarda xato jimgina qolib
// ketardi.

// Qaror funksiyasisiz certmagic HAR QANDAY nomga sertifikat
// chiqarardi. Bu ACME limitini yoqib yuborishning eng tez yo'li,
// shuning uchun sozlash bosqichidayoq to'siladi.
func TestNewACME_RequiresDecisionFunc(t *testing.T) {
	_, err := NewACME(ACMEOptions{
		Email:     "admin@cc01.uz",
		Directory: t.TempDir(),
	})
	if err == nil {
		t.Fatal("qaror funksiyasisiz sozlama qabul qilindi")
	}
	if !strings.Contains(err.Error(), "qaror") {
		t.Errorf("xato sababi tushunarsiz: %v", err)
	}
}

func TestNewACME_RequiresEmailAndDirectory(t *testing.T) {
	decide := func(string) bool { return true }

	if _, err := NewACME(ACMEOptions{Directory: t.TempDir(), Decide: decide}); err == nil {
		t.Error("emailsiz sozlama qabul qilindi")
	}
	if _, err := NewACME(ACMEOptions{Email: "admin@cc01.uz", Decide: decide}); err == nil {
		t.Error("papkasiz sozlama qabul qilindi")
	}
}

func TestNewACME_Builds(t *testing.T) {
	acme, err := NewACME(ACMEOptions{
		Email:     "admin@cc01.uz",
		Directory: t.TempDir(),
		CA:        LetsEncryptStaging,
		Decide:    func(string) bool { return true },
	})
	if err != nil {
		t.Fatalf("NewACME: %v", err)
	}
	if acme == nil {
		t.Fatal("nil qaytdi")
	}
}

// ⚠️ `acme-tls/1` NextProtos ga qo'shilmasa, ACME serveri
// TLS-ALPN-01 sinovini boshlay olmaydi va sertifikat HECH QACHON
// chiqmaydi — server esa hech qanday xato ko'rsatmaydi.
func TestTLSConfig_AdvertisesALPNChallenge(t *testing.T) {
	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	acme, err := NewACME(ACMEOptions{
		Email:     "admin@cc01.uz",
		Directory: t.TempDir(),
		CA:        LetsEncryptStaging,
		Decide:    func(string) bool { return true },
	})
	if err != nil {
		t.Fatalf("NewACME: %v", err)
	}

	config := TLSConfig(resolver, acme, "h2", "http/1.1")

	var found bool
	for _, proto := range config.NextProtos {
		if proto == acmez.ACMETLS1Protocol {
			found = true
		}
	}
	if !found {
		t.Errorf("acme-tls/1 e'lon qilinmadi: %v", config.NextProtos)
	}

	// Oddiy protokollar ham qolishi kerak.
	for _, want := range []string{"h2", "http/1.1"} {
		var kept bool
		for _, proto := range config.NextProtos {
			if proto == want {
				kept = true
			}
		}
		if !kept {
			t.Errorf("%s yo'qoldi: %v", want, config.NextProtos)
		}
	}
}

// ACME o'chiq bo'lsa sinov protokoli e'lon qilinmasligi kerak.
func TestTLSConfig_WithoutACME(t *testing.T) {
	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	config := TLSConfig(resolver, nil, "http/1.1")

	for _, proto := range config.NextProtos {
		if proto == acmez.ACMETLS1Protocol {
			t.Error("ACME o'chiq, lekin sinov protokoli e'lon qilindi")
		}
	}
	if config.GetCertificate == nil {
		t.Error("sertifikat tanlovchi berilmadi")
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion %d", config.MinVersion)
	}
}

// Oddiy trafik ACME yo'liga tushib qolmasligi kerak.
func TestTLSConfig_NormalTrafficGoesToResolver(t *testing.T) {
	wildcard := selfSigned(t, "*.cc01.uz")

	resolver, err := New(Options{Domain: "cc01.uz", Wildcard: wildcard})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	acme, err := NewACME(ACMEOptions{
		Email:     "admin@cc01.uz",
		Directory: t.TempDir(),
		CA:        LetsEncryptStaging,
		Decide:    func(string) bool { return true },
	})
	if err != nil {
		t.Fatalf("NewACME: %v", err)
	}

	config := TLSConfig(resolver, acme)

	got, err := config.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      "demo.cc01.uz",
		SupportedProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != wildcard {
		t.Error("oddiy trafik wildcard olmadi")
	}
}
