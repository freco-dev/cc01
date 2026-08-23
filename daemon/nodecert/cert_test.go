package nodecert

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Sertifikat bir marta yaratilib, keyin O'ZGARMASDAN qayta
// o'qilishi kerak. Aks holda demon har qayta ishga tushganda o'z
// identifikatorini yo'qotardi va CP uni begona deb rad etardi.
func TestLoad_IsStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()

	first, err := Load(dir)
	if err != nil {
		t.Fatalf("birinchi Load: %v", err)
	}

	second, err := Load(dir)
	if err != nil {
		t.Fatalf("ikkinchi Load: %v", err)
	}

	if Pin(first.Leaf) != Pin(second.Leaf) {
		t.Fatalf("sertifikat o'zgardi:\n  %s\n  %s", Pin(first.Leaf), Pin(second.Leaf))
	}
}

// Har bir node o'z kalitiga ega bo'lishi kerak.
func TestLoad_DistinctPerDirectory(t *testing.T) {
	first, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("birinchi: %v", err)
	}
	second, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("ikkinchi: %v", err)
	}

	if Pin(first.Leaf) == Pin(second.Leaf) {
		t.Fatal("ikkita node bir xil kalit oldi")
	}
}

// Kalit fayli faqat egasiga o'qilishi kerak: u nodening CP oldidagi
// yagona dalili.
func TestLoad_KeyIsPrivate(t *testing.T) {
	dir := t.TempDir()

	if _, err := Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	if mode := info.Mode().Perm(); mode != keyMode {
		t.Errorf("kalit ruxsatlari %o, %o kutilgan edi", mode, keyMode)
	}
}

// Sertifikat klient autentifikatsiyasi uchun yaroqli bo'lishi kerak.
func TestLoad_UsableForClientAuth(t *testing.T) {
	cert, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cert.Leaf == nil {
		t.Fatal("Leaf to'ldirilmagan — har ulanishda qayta parse qilinardi")
	}

	var found bool
	for _, usage := range cert.Leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Errorf("ClientAuth belgilanmagan: %v", cert.Leaf.ExtKeyUsage)
	}
}

// Pin formati CP tomonidagisi bilan bir xil bo'lishi shart.
func TestPin_UsesSharedFormat(t *testing.T) {
	cert, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	pin := Pin(cert.Leaf)
	if !strings.HasPrefix(pin, "sha256/") {
		t.Errorf("pin prefiksi noto'g'ri: %s", pin)
	}
	// base64(SHA-256) — 44 belgi, prefiks bilan 51.
	if len(pin) != len("sha256/")+44 {
		t.Errorf("pin uzunligi %d: %s", len(pin), pin)
	}
}

// Buzilgan sertifikat jimgina yangisi bilan almashtirilmasligi
// kerak: bu nodening identifikatorini yo'qotib, nosozlikni
// yashirardi.
func TestLoad_RefusesBrokenCertificate(t *testing.T) {
	dir := t.TempDir()

	if _, err := Load(dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, CertFile), []byte("bu sertifikat emas"), 0o644); err != nil {
		t.Fatalf("yozish: %v", err)
	}

	if _, err := Load(dir); err == nil {
		t.Fatal("buzilgan sertifikat qabul qilindi")
	}
}
