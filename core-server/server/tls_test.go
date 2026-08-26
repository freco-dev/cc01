package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/freco-dev/cc01/core-server/server"
	"github.com/freco-dev/cc01/core-server/tlsmgr"
)

// Bu testlar HAQIQIY TLS qo'l siqishi orqali ketadi: resolver'ning
// o'z testlari uni listener'ga to'g'ri ulanganini isbotlamaydi.

func cert(t *testing.T, names ...string) *tls.Certificate {
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

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  private,
		Leaf:        parsed,
	}
}

// startTLS resolver bilan listener ochadi va manzilini qaytaradi.
func startTLS(t *testing.T, resolver *tlsmgr.Resolver) string {
	t.Helper()

	var srv server.TCPServer
	err := srv.InitTLS(0, "test", &tls.Config{
		GetCertificate: resolver.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("InitTLS: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	go srv.Start(func(conn net.Conn) error {
		defer conn.Close()
		// Qo'l siqishini yakunlash uchun bitta bayt o'qiymiz.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		return nil
	})

	return fmt.Sprintf("127.0.0.1:%d", srv.Port())
}

// dialSNI berilgan SNI bilan ulanadi va ko'rsatilgan nomni qaytaradi.
func dialSNI(t *testing.T, addr, sni string) (string, error) {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // o'z-o'zini imzolagan test sertifikati
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("sertifikat kelmadi")
	}
	return certs[0].Subject.CommonName, nil
}

// Subdomain wildcard oladi, custom domain — o'zinikini.
func TestTLS_SelectsCertificateBySNI(t *testing.T) {
	resolver, err := tlsmgr.New(tlsmgr.Options{
		Domain:   "cc01.uz",
		Wildcard: cert(t, "*.cc01.uz"),
		Known:    func(name string) bool { return name == "app.mijoz.uz" },
		Issuer:   fixedIssuer{cert: cert(t, "app.mijoz.uz")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	addr := startTLS(t, resolver)

	cases := map[string]string{
		"demo.cc01.uz":   "*.cc01.uz",
		"boshqa.cc01.uz": "*.cc01.uz",
		"app.mijoz.uz":   "app.mijoz.uz",
	}

	for sni, want := range cases {
		got, err := dialSNI(t, addr, sni)
		if err != nil {
			t.Errorf("%s: %v", sni, err)
			continue
		}
		if got != want {
			t.Errorf("%s → %q, %q kutilgan edi", sni, got, want)
		}
	}
}

// Noma'lum domenga qo'l siqishi UZILISHI kerak.
//
// Bu resolver testidan farq qiladi: bu yerda yadro va TLS
// qatlami ham ishtirok etadi va xato klientgacha yetib borishi
// kerak.
func TestTLS_RefusesUnknownDomain(t *testing.T) {
	resolver, err := tlsmgr.New(tlsmgr.Options{
		Domain:   "cc01.uz",
		Wildcard: cert(t, "*.cc01.uz"),
		Known:    func(string) bool { return false },
		Issuer:   fixedIssuer{cert: cert(t, "begona.example.com")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	addr := startTLS(t, resolver)

	if name, err := dialSNI(t, addr, "begona.example.com"); err == nil {
		t.Errorf("qo'l siqishi o'tdi va %q sertifikati berildi", name)
	}
}

// Tunnel yopilgach sertifikat ham berilmasligi kerak.
func TestTLS_StopsServingWhenTunnelCloses(t *testing.T) {
	live := map[string]bool{"app.mijoz.uz": true}

	resolver, err := tlsmgr.New(tlsmgr.Options{
		Domain:   "cc01.uz",
		Wildcard: cert(t, "*.cc01.uz"),
		Known:    func(name string) bool { return live[name] },
		Issuer:   fixedIssuer{cert: cert(t, "app.mijoz.uz")},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	addr := startTLS(t, resolver)

	if _, err := dialSNI(t, addr, "app.mijoz.uz"); err != nil {
		t.Fatalf("tirik tunnel: %v", err)
	}

	// Tunnel yopildi.
	delete(live, "app.mijoz.uz")

	if name, err := dialSNI(t, addr, "app.mijoz.uz"); err == nil {
		t.Errorf("tunnel yopilgach ham %q berildi", name)
	}
}

// fixedIssuer — doim bitta sertifikat qaytaradi.
type fixedIssuer struct{ cert *tls.Certificate }

func (f fixedIssuer) Certificate(context.Context, string) (*tls.Certificate, error) {
	return f.cert, nil
}
