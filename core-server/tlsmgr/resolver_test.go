package tlsmgr

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// selfSigned test uchun sertifikat yasaydi.
func selfSigned(t *testing.T, names ...string) *tls.Certificate {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("kalit: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatalf("sertifikat: %v", err)
	}

	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
}

// fakeIssuer — chaqiruvlarni sanaydigan chiqaruvchi.
type fakeIssuer struct {
	t     *testing.T
	calls map[string]int
	fail  error
}

func newIssuer(t *testing.T) *fakeIssuer {
	return &fakeIssuer{t: t, calls: make(map[string]int)}
}

func (f *fakeIssuer) Certificate(_ context.Context, name string) (*tls.Certificate, error) {
	f.calls[name]++
	if f.fail != nil {
		return nil, f.fail
	}
	return selfSigned(f.t, name), nil
}

func hello(name string) *tls.ClientHelloInfo {
	info := &tls.ClientHelloInfo{ServerName: name}
	return info
}

// ── Wildcard ───────────────────────────────────────────────────

func TestResolver_SubdomainUsesWildcard(t *testing.T) {
	wildcard := selfSigned(t, "*.cc01.uz")

	resolver, err := New(Options{Domain: "cc01.uz", Wildcard: wildcard})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := resolver.GetCertificate(hello("demo.cc01.uz"))
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != wildcard {
		t.Error("wildcard sertifikat qaytmadi")
	}
}

// Wildcard FAQAT bitta yorliqni qoplaydi (RFC 6125 §6.4.3).
// Chuqurroq nomga uni bersak, brauzer nomni mos kelmagan deb rad
// etardi — ya'ni server jimgina yaroqsiz sertifikat ko'rsatardi.
func TestResolver_WildcardCoversOneLabelOnly(t *testing.T) {
	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := resolver.GetCertificate(hello("a.b.cc01.uz")); !errors.Is(err, ErrUnknownName) {
		t.Errorf("ikki yorliqli nomga wildcard berildi: %v", err)
	}
}

// Apex wildcard ostida EMAS: `*.cc01.uz` `cc01.uz` ni qoplamaydi.
func TestResolver_ApexIsSeparate(t *testing.T) {
	wildcard := selfSigned(t, "*.cc01.uz")
	apex := selfSigned(t, "cc01.uz")

	resolver, err := New(Options{Domain: "cc01.uz", Wildcard: wildcard, Apex: apex})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := resolver.GetCertificate(hello("cc01.uz"))
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != apex {
		t.Error("apex uchun wildcard qaytdi")
	}
}

// ── SNI ────────────────────────────────────────────────────────

// SNI siz ulanish rad etilishi kerak.
func TestResolver_RejectsMissingSNI(t *testing.T) {
	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := resolver.GetCertificate(hello("")); !errors.Is(err, ErrUnknownName) {
		t.Errorf("SNI siz ulanish qabul qilindi: %v", err)
	}
}

// Nuqta bilan tugagan nom ham (FQDN shakli) ishlashi kerak.
func TestResolver_AcceptsTrailingDot(t *testing.T) {
	wildcard := selfSigned(t, "*.cc01.uz")

	resolver, err := New(Options{Domain: "cc01.uz", Wildcard: wildcard})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := resolver.GetCertificate(hello("demo.cc01.uz.")); err != nil {
		t.Errorf("FQDN shakli rad etildi: %v", err)
	}
}

func TestResolver_RejectsMalformedNames(t *testing.T) {
	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
		Known:    func(string) bool { return true },
		Issuer:   newIssuer(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	bad := []string{
		"demo..cc01.uz",
		"demo cc01.uz",
		"demo/../etc",
		"\u0434emo.cc01.uz", // lotin bo'lmagan belgi (ataylab escape bilan)
		string(make([]byte, 300)),
	}

	for _, name := range bad {
		if _, err := resolver.GetCertificate(hello(name)); !errors.Is(err, ErrUnknownName) {
			t.Errorf("%q qabul qilindi: %v", name, err)
		}
	}
}

// ── Custom domain ──────────────────────────────────────────────

// ⚠️ Bu Faza 3 dagi eng jiddiy xavfsizlik tekshiruvi. Ro'yxatdan
// o'tmagan domenga sertifikat chiqarsak, kimdir o'z DNS'ini bizga
// qaratib, ACME limitlarini yoqib yuborardi va haqiqiy mijozlar
// sertifikat ololmay qolardi.
func TestResolver_RefusesUnknownCustomDomain(t *testing.T) {
	issuer := newIssuer(t)

	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
		Known:    func(name string) bool { return name == "app.mijoz.uz" },
		Issuer:   issuer,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := resolver.GetCertificate(hello("begona.example.com")); !errors.Is(err, ErrUnknownName) {
		t.Errorf("begona domen qabul qilindi: %v", err)
	}
	if len(issuer.calls) != 0 {
		t.Errorf("chiqaruvchi chaqirildi: %v", issuer.calls)
	}
}

func TestResolver_IssuesForKnownCustomDomain(t *testing.T) {
	issuer := newIssuer(t)

	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
		Known:    func(name string) bool { return name == "app.mijoz.uz" },
		Issuer:   issuer,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := resolver.GetCertificate(hello("app.mijoz.uz")); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if issuer.calls["app.mijoz.uz"] != 1 {
		t.Errorf("chiqaruvchi %d marta chaqirildi", issuer.calls["app.mijoz.uz"])
	}
}

// Known berilmasa custom domainlarga UMUMAN xizmat qilinmasligi
// kerak — "hammasiga ha" degan sukut xavfli bo'lardi.
func TestResolver_NoKnownFuncMeansNoCustomDomains(t *testing.T) {
	issuer := newIssuer(t)

	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
		Issuer:   issuer,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := resolver.GetCertificate(hello("app.mijoz.uz")); !errors.Is(err, ErrUnknownName) {
		t.Errorf("Known siz custom domen qabul qilindi: %v", err)
	}
	if len(issuer.calls) != 0 {
		t.Errorf("chiqaruvchi chaqirildi: %v", issuer.calls)
	}
}

// ── Chiqaruvchi ────────────────────────────────────────────────

// Resolver ATAYLAB keshlamaydi: chiqaruvchi sertifikatni fon
// rejimida yangilaydi va bizdagi nusxa eskirib qolardi.
func TestResolver_DoesNotCache(t *testing.T) {
	issuer := newIssuer(t)

	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
		Known:    func(string) bool { return true },
		Issuer:   issuer,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for range 3 {
		if _, err := resolver.GetCertificate(hello("app.mijoz.uz")); err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
	}

	if got := issuer.calls["app.mijoz.uz"]; got != 3 {
		t.Errorf("chiqaruvchi %d marta chaqirildi, 3 kutilgan edi", got)
	}
}

// Ruxsat HAR BIR qo'l siqishida qayta tekshirilishi kerak: tunnel
// yopilishi bilan sertifikat berish darhol to'xtashi kerak.
func TestResolver_RechecksPermissionEveryTime(t *testing.T) {
	live := map[string]bool{"app.mijoz.uz": true}

	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
		Known:    func(name string) bool { return live[name] },
		Issuer:   newIssuer(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := resolver.GetCertificate(hello("app.mijoz.uz")); err != nil {
		t.Fatalf("tirik tunnel: %v", err)
	}

	delete(live, "app.mijoz.uz")

	if _, err := resolver.GetCertificate(hello("app.mijoz.uz")); !errors.Is(err, ErrUnknownName) {
		t.Errorf("tunnel yopilgach ham sertifikat berildi: %v", err)
	}
}

// Chiqaruvchi yiqilsa xato yuqoriga chiqishi kerak.
func TestResolver_IssuerFailurePropagates(t *testing.T) {
	issuer := newIssuer(t)
	issuer.fail = errors.New("ACME javob bermadi")

	resolver, err := New(Options{
		Domain:   "cc01.uz",
		Wildcard: selfSigned(t, "*.cc01.uz"),
		Known:    func(string) bool { return true },
		Issuer:   issuer,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := resolver.GetCertificate(hello("app.mijoz.uz")); err == nil {
		t.Fatal("xato kutilgan edi")
	}
}

// ── Sozlash ────────────────────────────────────────────────────

// Na sertifikat, na chiqaruvchi berilmasa resolver hech bir nomga
// xizmat qila olmaydi — buni ishga tushishda aytish kerak.
func TestNew_RejectsUselessConfig(t *testing.T) {
	if _, err := New(Options{Domain: "cc01.uz"}); err == nil {
		t.Error("bo'sh sozlama qabul qilindi")
	}
	if _, err := New(Options{Wildcard: selfSigned(t, "*.cc01.uz")}); err == nil {
		t.Error("domensiz sozlama qabul qilindi")
	}
}
