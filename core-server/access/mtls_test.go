package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/freco-dev/cc01/core-server/config"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// ─────────────────── sinov sertifikatlari (ECDSA P-256) ───────────────────

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CA yaratish: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("CA o'qish: %v", err)
	}
	return &testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issue CA imzolagan leaf sertifikat chiqaradi va uni PEM (sertifikat,
// PKCS#8 kalit) ko'rinishida qaytaradi.
func (ca *testCA) issue(t *testing.T, cn string, eku x509.ExtKeyUsage, hosts ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{
		SerialNumber: serial(t),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("sertifikat yaratish: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("kalitni kodlash: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func (ca *testCA) issueServer(t *testing.T) tls.Certificate {
	t.Helper()
	certPEM, keyPEM := ca.issue(t, "access-server", x509.ExtKeyUsageServerAuth, "127.0.0.1", "localhost")
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("server juftligi: %v", err)
	}
	return pair
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("kalit yaratish: %v", err)
	}
	return key
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatalf("seriya: %v", err)
	}
	return n
}

// ─────────────────────── TLS ustidagi haqiqiy gRPC server ───────────────────────

// tlsAccessServer — AP o'rnida: haqiqiy TCP listener, mTLS majburiy
// (RequireAndVerifyClientCert) va ko'rilgan klient CN'larini yozib boradi.
type tlsAccessServer struct {
	addr string

	mu      sync.Mutex
	peerCNs []string
}

func (s *tlsAccessServer) seenCNs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.peerCNs...)
}

func startTLSAccessServer(t *testing.T, fake *fakeAccessServer, serverCert tls.Certificate, clientCA *testCA) *tlsAccessServer {
	t.Helper()

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientCA.cert)

	srv := &tlsAccessServer{}
	recordPeer := func(
		ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
	) (any, error) {
		if p, ok := peer.FromContext(ctx); ok {
			if info, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(info.State.VerifiedChains) > 0 {
				srv.mu.Lock()
				srv.peerCNs = append(srv.peerCNs, info.State.VerifiedChains[0][0].Subject.CommonName)
				srv.mu.Unlock()
			}
		}
		return handler(ctx, req)
	}

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
			MinVersion:   tls.VersionTLS13,
		})),
		grpc.UnaryInterceptor(recordPeer),
	)
	cc01v1.RegisterAccessInternalServiceServer(server, fake)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.addr = listener.Addr().String()
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return srv
}

// mtlsEnv — bitta mTLS sinovi uchun to'plam: AP CA, edge CA va edge
// klient sertifikati.
type mtlsEnv struct {
	apCA      *testCA
	edgeCA    *testCA
	clientPEM []byte
	clientKey []byte
}

func newMTLSEnv(t *testing.T) *mtlsEnv {
	t.Helper()
	env := &mtlsEnv{
		apCA:   newTestCA(t, "cc01 test AP CA"),
		edgeCA: newTestCA(t, "cc01 test edge CA"),
	}
	env.clientPEM, env.clientKey = env.edgeCA.issue(t, "edge-test", x509.ExtKeyUsageClientAuth)
	return env
}

// clientTLS edge klient sozlamasini config bilan AYNAN bir xil yo'l
// orqali quradi (config.AccessClientTLS).
func (env *mtlsEnv) clientTLS(t *testing.T, serverName string) *tls.Config {
	t.Helper()
	tlsConfig, _, err := config.AccessClientTLS(env.apCA.pem, env.clientPEM, env.clientKey, serverName)
	if err != nil {
		t.Fatalf("AccessClientTLS: %v", err)
	}
	return tlsConfig
}

func dialTLS(t *testing.T, addr string, tlsConfig *tls.Config) *Client {
	t.Helper()
	client, err := Dial(Options{Address: addr, Timeout: 2 * time.Second, Grace: time.Minute, TLS: tlsConfig})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// To'g'ri mTLS: AP sertifikati ichki CA bilan tasdiqlanadi, edge o'z
// sertifikatini ko'rsatadi va AP uning CN'ini ko'radi.
func TestMTLS_ValidAuthorizes(t *testing.T) {
	t.Parallel()
	env := newMTLSEnv(t)
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	srv := startTLSAccessServer(t, fake, env.apCA.issueServer(t), env.edgeCA)

	for _, serverName := range []string{"127.0.0.1", "localhost"} {
		client := dialTLS(t, srv.addr, env.clientTLS(t, serverName))

		grant, err := client.Authorize(context.Background(), Request{Token: "tok", Subdomain: "myapp"})
		if err != nil {
			t.Fatalf("server_name=%s: kutilmagan xato: %v", serverName, err)
		}
		if grant.Subdomain != "myapp" {
			t.Errorf("subdomain: %q olindi", grant.Subdomain)
		}
	}

	cns := srv.seenCNs()
	if len(cns) != 2 {
		t.Fatalf("server 2 ta chaqiruv ko'rishi kerak edi, %d: %v", len(cns), cns)
	}
	for _, cn := range cns {
		if cn != "edge-test" {
			t.Errorf("server ko'rgan klient CN: %q, edge-test kutilgan", cn)
		}
	}
}

// AP sertifikati begona CA'dan — handshake yiqiladi. Bu rad javobi
// (Denial) EMAS, tarmoq xatosi: Authorize fail-static yo'liga, Renew esa
// ErrUnavailable'ga tushadi (ochiq tunnel yopilmaydi).
func TestMTLS_ServerCertFromOtherCAFails(t *testing.T) {
	t.Parallel()
	env := newMTLSEnv(t)
	rogue := newTestCA(t, "rogue CA")
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	srv := startTLSAccessServer(t, fake, rogue.issueServer(t), env.edgeCA)

	client := dialTLS(t, srv.addr, env.clientTLS(t, "127.0.0.1"))

	_, err := client.Authorize(context.Background(), Request{Token: "tok", Subdomain: "myapp"})
	assertTransportFailure(t, err)

	_, err = client.Renew(context.Background(), Request{Token: "tok", Subdomain: "myapp"})
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("Renew: ErrUnavailable kutilgan, olindi: %v", err)
	}
	if n := fake.calls.Load(); n != 0 {
		t.Errorf("begona AP'ga so'rov yetib bormasligi kerak edi, %d ta yetdi", n)
	}
}

// Server nomi AP sertifikatiga mos kelmasa (SAN'da yo'q) — yiqiladi.
func TestMTLS_WrongServerNameFails(t *testing.T) {
	t.Parallel()
	env := newMTLSEnv(t)
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	srv := startTLSAccessServer(t, fake, env.apCA.issueServer(t), env.edgeCA)

	client := dialTLS(t, srv.addr, env.clientTLS(t, "ap.internal"))

	_, err := client.Authorize(context.Background(), Request{Token: "tok", Subdomain: "myapp"})
	assertTransportFailure(t, err)
	if n := fake.calls.Load(); n != 0 {
		t.Errorf("so'rov yetib bormasligi kerak edi, %d ta yetdi", n)
	}
}

// Edge sertifikati AP ishonmaydigan CA'dan — AP ulanishni rad etadi.
func TestMTLS_ClientCertFromOtherCAFails(t *testing.T) {
	t.Parallel()
	env := newMTLSEnv(t)
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	srv := startTLSAccessServer(t, fake, env.apCA.issueServer(t), newTestCA(t, "AP faqat shunga ishonadi"))

	client := dialTLS(t, srv.addr, env.clientTLS(t, "127.0.0.1"))

	_, err := client.Authorize(context.Background(), Request{Token: "tok", Subdomain: "myapp"})
	assertTransportFailure(t, err)
	if n := fake.calls.Load(); n != 0 {
		t.Errorf("so'rov yetib bormasligi kerak edi, %d ta yetdi", n)
	}
}

func assertTransportFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("xato kutilgan edi: TLS tekshiruvi o'tmasligi kerak")
	}
	var denial *Denial
	if errors.As(err, &denial) {
		t.Fatalf("tarmoq xatosi kutilgan, rad javobi olindi: %v", err)
	}
	t.Logf("kutilgan xato: %v", err)
}

// Ikkinchi himoya qatlami: config'ni chetlab Dial chaqirilsa ham
// loopback bo'lmagan manzilga shifrsiz ulanilmaydi.
func TestDial_RefusesPlaintextToNonLoopback(t *testing.T) {
	for _, addr := range []string{
		"10.0.0.5:5081",
		"ap.internal:5081",
		"dns:///ap.internal:5081",
		"passthrough:///bufnet",
		"unix:///run/ap.sock",
		"",
	} {
		if client, err := Dial(Options{Address: addr}); err == nil {
			_ = client.Close()
			t.Errorf("%q: shifrsiz Dial rad etilishi kerak edi", addr)
		}
	}

	for _, addr := range []string{
		"127.0.0.1:5081",
		"127.8.9.10:5081",
		"[::1]:5081",
		"localhost:5081",
		"dns:///localhost:5081",
	} {
		client, err := Dial(Options{Address: addr})
		if err != nil {
			t.Errorf("%q: loopback'ga shifrsiz Dial ruxsat etilishi kerak edi: %v", addr, err)
			continue
		}
		_ = client.Close()
	}
}

// TLS sozlamasi berilgan bo'lsa ham u ichki CA va klient sertifikatisiz
// qabul qilinmaydi.
func TestDial_RefusesWeakTLSConfig(t *testing.T) {
	env := newMTLSEnv(t)
	good := env.clientTLS(t, "ap.internal")

	noRoots := good.Clone()
	noRoots.RootCAs = nil
	skip := good.Clone()
	skip.InsecureSkipVerify = true
	noCert := good.Clone()
	noCert.Certificates = nil

	for name, cfg := range map[string]*tls.Config{
		"RootCAs yo'q":         noRoots,
		"InsecureSkipVerify":   skip,
		"klient sertifikatsiz": noCert,
	} {
		if client, err := Dial(Options{Address: "ap.internal:5081", TLS: cfg}); err == nil {
			_ = client.Close()
			t.Errorf("%s: Dial rad etishi kerak edi", name)
		}
	}

	client, err := Dial(Options{Address: "ap.internal:5081", TLS: good})
	if err != nil {
		t.Fatalf("to'g'ri mTLS bilan loopback bo'lmagan manzil ruxsat etilishi kerak: %v", err)
	}
	_ = client.Close()
}

// startTLS12AccessServer — macOS'dagi .NET AP kabi faqat TLS 1.2 da
// gaplashadigan server.
func startTLS12AccessServer(t *testing.T, fake *fakeAccessServer, serverCert tls.Certificate, clientCA *testCA) string {
	t.Helper()
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientCA.cert)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MaxVersion:   tls.VersionTLS12,
	})))
	cc01v1.RegisterAccessInternalServiceServer(server, fake)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return listener.Addr().String()
}

// TLS 1.2 faqat oshkora so'ralganda (MinVersion=1.2) va faqat loopback
// manzilda ishlaydi. Sukut (1.3) TLS 1.2-only serverga ulanmaydi.
func TestMTLS_TLS12OnlyOnLoopbackWhenRequested(t *testing.T) {
	t.Parallel()
	env := newMTLSEnv(t)
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	addr := startTLS12AccessServer(t, fake, env.apCA.issueServer(t), env.edgeCA)

	// Sukut: TLS 1.3 → 1.2-only server bilan handshake bo'lmaydi.
	_, err := dialTLS(t, addr, env.clientTLS(t, "127.0.0.1")).
		Authorize(context.Background(), Request{Token: "tok", Subdomain: "myapp"})
	assertTransportFailure(t, err)

	// Loopback + MinVersion=1.2 → ishlaydi.
	tls12 := env.clientTLS(t, "127.0.0.1")
	tls12.MinVersion = tls.VersionTLS12
	if _, err := dialTLS(t, addr, tls12).
		Authorize(context.Background(), Request{Token: "tok", Subdomain: "myapp"}); err != nil {
		t.Fatalf("loopback + TLS 1.2: kutilmagan xato: %v", err)
	}
}

// Ikkinchi himoya qatlami: config chetlab o'tilsa ham (Dial'ni boshqa kod
// chaqirsa) tarmoq manzilida TLS 1.2 so'rovi 1.3 ga ko'tariladi.
func TestMTLS_TLS12RaisedTo13ForNonLoopback(t *testing.T) {
	t.Parallel()
	env := newMTLSEnv(t)
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	real := startTLS12AccessServer(t, fake, env.apCA.issueServer(t), env.edgeCA)

	tls12 := env.clientTLS(t, "127.0.0.1")
	tls12.MinVersion = tls.VersionTLS12
	client, err := Dial(Options{
		Address: "passthrough:///ap.internal:5081", // loopback EMAS
		Timeout: 2 * time.Second,
		Grace:   time.Minute,
		TLS:     tls12,
		DialOptions: []grpc.DialOption{grpc.WithContextDialer(
			func(ctx context.Context, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", real)
			})},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Authorize(context.Background(), Request{Token: "tok", Subdomain: "myapp"})
	assertTransportFailure(t, err)
	if fake.calls.Load() != 0 {
		t.Errorf("TLS 1.2 tarmoq manzilida o'tib ketdi: %d chaqiruv", fake.calls.Load())
	}
}
