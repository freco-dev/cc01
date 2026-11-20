package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// accessTLSFiles — sinov uchun diskka yozilgan CA va edge klient
// sertifikati (ECDSA P-256, PKCS#8).
type accessTLSFiles struct {
	ca, cert, key string
}

func writeAccessTLSFiles(t *testing.T) accessTLSFiles {
	t.Helper()
	return writeAccessTLSFilesWith(t, "edge-test", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Hour)
}

func writeAccessTLSFilesWith(t *testing.T, cn string, eku []x509.ExtKeyUsage, validFor time.Duration) accessTLSFiles {
	t.Helper()
	dir := t.TempDir()

	caKey := testKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cc01 test CA"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	key := testKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sertifikat: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("kalit: %v", err)
	}

	files := accessTLSFiles{
		ca:   filepath.Join(dir, "ca.pem"),
		cert: filepath.Join(dir, "edge.pem"),
		key:  filepath.Join(dir, "edge.key"),
	}
	writePEM(t, files.ca, "CERTIFICATE", caDER)
	writePEM(t, files.cert, "CERTIFICATE", der)
	writePEM(t, files.key, "PRIVATE KEY", keyDER)
	return files
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("kalit yaratish: %v", err)
	}
	return key
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("yozish: %v", err)
	}
}

// loadAccess avtorizatsiya yoqilgan muhitda (berilgan manzil va TLS
// o'zgaruvchilari bilan) konfiguratsiyani yuklaydi.
func loadAccess(t *testing.T, addr string, env map[string]string) (Config, error) {
	t.Helper()
	full := map[string]string{
		"CC01_AUTH_MODE":   "",
		"CC01_ACCESS_ADDR": addr,
	}
	for k, v := range env {
		full[k] = v
	}
	return loadRaw(t, full)
}

func tlsEnv(f accessTLSFiles) map[string]string {
	return map[string]string{
		"CC01_ACCESS_TLS_CA":   f.ca,
		"CC01_ACCESS_TLS_CERT": f.cert,
		"CC01_ACCESS_TLS_KEY":  f.key,
	}
}

func TestLoad_AccessTLSEnabled(t *testing.T) {
	files := writeAccessTLSFiles(t)

	cfg, err := loadAccess(t, "ap.internal:5081", tlsEnv(files))
	if err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}

	tc := cfg.AccessTLS
	if tc == nil {
		t.Fatal("AccessTLS to'ldirilishi kerak edi")
	}
	if tc.ServerName != "ap.internal" {
		t.Errorf("ServerName: CC01_ACCESS_ADDR host qismi kutilgan, %q olindi", tc.ServerName)
	}
	if tc.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion: TLS 1.3 kutilgan, %x olindi", tc.MinVersion)
	}
	if tc.RootCAs == nil {
		t.Error("RootCAs: faqat ichki CA bo'lishi kerak, nil (tizim ildizlari) olindi")
	}
	if tc.InsecureSkipVerify {
		t.Error("InsecureSkipVerify yoqilmasligi kerak")
	}
	if len(tc.Certificates) != 1 {
		t.Fatalf("bitta klient sertifikati kutilgan, %d olindi", len(tc.Certificates))
	}

	info := cfg.AccessTLSInfo
	if info == nil || info.ClientCN != "edge-test" || info.CAFile != files.ca || info.ServerName != "ap.internal" {
		t.Errorf("AccessTLSInfo noto'g'ri: %+v", info)
	}
}

func TestLoad_AccessTLSServerNameOverride(t *testing.T) {
	files := writeAccessTLSFiles(t)
	env := tlsEnv(files)
	env["CC01_ACCESS_TLS_SERVER_NAME"] = "access-server"

	cfg, err := loadAccess(t, "10.0.0.5:5081", env)
	if err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}
	if cfg.AccessTLS.ServerName != "access-server" {
		t.Errorf("ServerName: %q olindi", cfg.AccessTLS.ServerName)
	}
}

func TestLoad_AccessTLSServerNameDefaultsToIP(t *testing.T) {
	files := writeAccessTLSFiles(t)

	cfg, err := loadAccess(t, "[::1]:5081", tlsEnv(files))
	if err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}
	if cfg.AccessTLS.ServerName != "::1" {
		t.Errorf("ServerName: %q olindi", cfg.AccessTLS.ServerName)
	}
}

// Uchtadan birortasi berilsa mTLS yoqiladi va qolganlari majburiy.
func TestLoad_AccessTLSPartialFails(t *testing.T) {
	files := writeAccessTLSFiles(t)
	cases := []struct {
		name    string
		env     map[string]string
		missing []string
	}{
		{"faqat CERT", map[string]string{"CC01_ACCESS_TLS_CERT": files.cert},
			[]string{"CC01_ACCESS_TLS_CA", "CC01_ACCESS_TLS_KEY"}},
		{"faqat CA", map[string]string{"CC01_ACCESS_TLS_CA": files.ca},
			[]string{"CC01_ACCESS_TLS_CERT", "CC01_ACCESS_TLS_KEY"}},
		{"KEY yo'q", map[string]string{"CC01_ACCESS_TLS_CA": files.ca, "CC01_ACCESS_TLS_CERT": files.cert},
			[]string{"CC01_ACCESS_TLS_KEY"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Loopback manzilda ham: qisman sozlama jimgina shifrsizga
			// tushib qolmasligi kerak.
			_, err := loadAccess(t, "127.0.0.1:5081", tc.env)
			if err == nil {
				t.Fatal("xato kutilgan edi")
			}
			for _, name := range tc.missing {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("xato %s ni nomlashi kerak, olindi: %v", name, err)
				}
			}
		})
	}
}

// O'qib bo'lmaydigan yoki noto'g'ri fayl server ishga tushishini
// to'xtatadi va xato tegishli o'zgaruvchini nomlaydi.
func TestLoad_AccessTLSBadFilesNameVariable(t *testing.T) {
	files := writeAccessTLSFiles(t)
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("bu PEM emas\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := writeAccessTLSFiles(t) // boshqa kalit — sertifikatga mos emas
	missing := filepath.Join(t.TempDir(), "yoq.pem")

	cases := []struct {
		name     string
		override map[string]string
		wantVar  string
	}{
		{"CA fayli yo'q", map[string]string{"CC01_ACCESS_TLS_CA": missing}, "CC01_ACCESS_TLS_CA"},
		{"CA PEM emas", map[string]string{"CC01_ACCESS_TLS_CA": garbage}, "CC01_ACCESS_TLS_CA"},
		{"CERT fayli yo'q", map[string]string{"CC01_ACCESS_TLS_CERT": missing}, "CC01_ACCESS_TLS_CERT"},
		{"CERT PEM emas", map[string]string{"CC01_ACCESS_TLS_CERT": garbage}, "CC01_ACCESS_TLS_CERT"},
		{"KEY fayli yo'q", map[string]string{"CC01_ACCESS_TLS_KEY": missing}, "CC01_ACCESS_TLS_KEY"},
		{"KEY PEM emas", map[string]string{"CC01_ACCESS_TLS_KEY": garbage}, "CC01_ACCESS_TLS_KEY"},
		{"KEY mos emas", map[string]string{"CC01_ACCESS_TLS_KEY": other.key}, "CC01_ACCESS_TLS_KEY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tlsEnv(files)
			for k, v := range tc.override {
				env[k] = v
			}
			_, err := loadAccess(t, "ap.internal:5081", env)
			if err == nil {
				t.Fatal("xato kutilgan edi")
			}
			if !strings.Contains(err.Error(), tc.wantVar) {
				t.Errorf("xato %s ni nomlashi kerak, olindi: %v", tc.wantVar, err)
			}
		})
	}
}

// AP qabul qilmaydigan klient sertifikati ishga tushishda rad etiladi.
func TestLoad_AccessTLSRejectsUnusableClientCert(t *testing.T) {
	cases := []struct {
		name  string
		files accessTLSFiles
		want  string
	}{
		{"CN yo'q", writeAccessTLSFilesWith(t, "", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Hour), "CN"},
		{"clientAuth yo'q", writeAccessTLSFilesWith(t, "edge-test", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Hour), "clientAuth"},
		{"muddati tugagan", writeAccessTLSFilesWith(t, "edge-test", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, -time.Hour), "muddati"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadAccess(t, "ap.internal:5081", tlsEnv(tc.files))
			if err == nil {
				t.Fatal("xato kutilgan edi")
			}
			if !strings.Contains(err.Error(), "CC01_ACCESS_TLS_CERT") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("xato CC01_ACCESS_TLS_CERT va %q ni o'z ichiga olishi kerak, olindi: %v", tc.want, err)
			}
		})
	}
}

// mTLS'siz faqat loopback manzil ruxsat etiladi (DEV_SPEC S-11).
func TestLoad_AccessPlaintextOnlyOnLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:5081", "127.0.0.53:5081", "[::1]:5081", "localhost:5081", "LOCALHOST:5081"} {
		t.Run(addr, func(t *testing.T) {
			cfg, err := loadAccess(t, addr, nil)
			if err != nil {
				t.Fatalf("loopback shifrsiz ruxsat etilishi kerak: %v", err)
			}
			if cfg.AccessTLS != nil || cfg.AccessTLSInfo != nil {
				t.Error("AccessTLS nil bo'lishi kerak edi")
			}
		})
	}

	for _, addr := range []string{"10.0.0.5:5081", "ap.internal:5081", "0.0.0.0:5081", "[::]:5081", "localhost.evil.com:5081"} {
		t.Run(addr, func(t *testing.T) {
			_, err := loadAccess(t, addr, nil)
			if err == nil {
				t.Fatal("xato kutilgan edi: loopback emas va mTLS yo'q")
			}
			if !strings.Contains(err.Error(), "loopback emas va mTLS sozlanmagan") {
				t.Errorf("xato sababni aytishi kerak, olindi: %v", err)
			}
		})
	}
}

func TestLoad_AccessAddrWithoutPortFails(t *testing.T) {
	_, err := loadAccess(t, "127.0.0.1", nil)
	if err == nil || !strings.Contains(err.Error(), "CC01_ACCESS_ADDR") {
		t.Fatalf("CC01_ACCESS_ADDR xatosi kutilgan, olindi: %v", err)
	}
}

// SERVER_NAME yolg'iz — ehtimol chala sozlama: jimgina e'tiborsiz
// qoldirilmaydi.
func TestLoad_AccessTLSServerNameAloneFails(t *testing.T) {
	_, err := loadAccess(t, "127.0.0.1:5081", map[string]string{"CC01_ACCESS_TLS_SERVER_NAME": "ap"})
	if err == nil || !strings.Contains(err.Error(), "CC01_ACCESS_TLS_SERVER_NAME") {
		t.Fatalf("CC01_ACCESS_TLS_SERVER_NAME xatosi kutilgan, olindi: %v", err)
	}
}

// AUTH_MODE=disabled: AP'ga ulanish yo'q — TLS o'zgaruvchilari (hatto
// noto'g'ri bo'lsa ham) e'tiborsiz qoldiriladi.
func TestLoad_AuthDisabledIgnoresAccessTLS(t *testing.T) {
	cfg, err := loadRaw(t, map[string]string{
		"CC01_AUTH_MODE":       "disabled",
		"CC01_ACCESS_ADDR":     "ap.internal:5081",
		"CC01_ACCESS_TLS_CERT": filepath.Join(t.TempDir(), "yoq.pem"),
	})
	if err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}
	if cfg.AccessTLS != nil || cfg.AccessTLSInfo != nil {
		t.Error("AUTH_MODE=disabled da AccessTLS nil bo'lishi kerak")
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:5081":             true,
		"127.255.255.254:1":          true,
		"[::1]:5081":                 true,
		"[::ffff:127.0.0.1]:5081":    true,
		"localhost:5081":             true,
		"dns:///localhost:5081":      true,
		"passthrough:///127.0.0.1:0": true,
		"127.0.0.1":                  false, // port yo'q
		"10.0.0.1:5081":              false,
		"[::]:5081":                  false,
		"ap.internal:5081":           false,
		"unix:///run/ap.sock":        false,
		"":                           false,
	}
	for addr, want := range cases {
		if got := IsLoopbackAddr(addr); got != want {
			t.Errorf("IsLoopbackAddr(%q) = %v, %v kutilgan", addr, got, want)
		}
	}
}

// CC01_ACCESS_TLS_MIN=1.2 — faqat loopback'dagi AP uchun (macOS dev AP
// server tomonda TLS 1.3 ni qo'llamaydi). Tarmoq manzilida, noma'lum
// qiymatda yoki mTLS'siz — ishga tushmaydi.
func TestLoad_AccessTLSMin(t *testing.T) {
	files := writeAccessTLSFiles(t)
	with := func(min string) map[string]string {
		env := tlsEnv(files)
		env["CC01_ACCESS_TLS_MIN"] = min
		return env
	}

	cfg, err := loadAccess(t, "127.0.0.1:5081", with("1.2"))
	if err != nil {
		t.Fatalf("loopback + 1.2: kutilmagan xato: %v", err)
	}
	if cfg.AccessTLS.MinVersion != tls.VersionTLS12 || cfg.AccessTLSInfo.MinVersion != "1.2" {
		t.Errorf("loopback + 1.2: MinVersion=%x info=%q", cfg.AccessTLS.MinVersion, cfg.AccessTLSInfo.MinVersion)
	}

	cfg, err = loadAccess(t, "127.0.0.1:5081", with("1.3"))
	if err != nil || cfg.AccessTLS.MinVersion != tls.VersionTLS13 {
		t.Errorf("1.3: err=%v MinVersion=%x", err, cfg.AccessTLS.MinVersion)
	}

	if _, err := loadAccess(t, "ap.internal:5081", with("1.2")); err == nil ||
		!strings.Contains(err.Error(), "faqat loopback") {
		t.Errorf("tarmoq manzili + 1.2 rad etilishi kerak edi, olindi: %v", err)
	}
	for _, bad := range []string{"1.1", "1.0", "tls13", " 1.2"} {
		if _, err := loadAccess(t, "127.0.0.1:5081", with(bad)); err == nil ||
			!strings.Contains(err.Error(), "CC01_ACCESS_TLS_MIN") {
			t.Errorf("%q rad etilishi kerak edi, olindi: %v", bad, err)
		}
	}
	if _, err := loadAccess(t, "127.0.0.1:5081", map[string]string{"CC01_ACCESS_TLS_MIN": "1.2"}); err == nil ||
		!strings.Contains(err.Error(), "CC01_ACCESS_TLS_MIN") {
		t.Errorf("mTLS'siz CC01_ACCESS_TLS_MIN rad etilishi kerak edi, olindi: %v", err)
	}
}
