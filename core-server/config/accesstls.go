package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
)

// Edge → access-server kanalining mTLS sozlamalari (DEV_SPEC §7.2 S-11,
// A-S5).
//
// Kanal ikki holatda bo'lishi mumkin:
//
//   - mTLS — CC01_ACCESS_TLS_CA, CC01_ACCESS_TLS_CERT, CC01_ACCESS_TLS_KEY
//     dan birortasi berilgan bo'lsa yoqiladi va unda UCHALASI ham majburiy.
//     AP sertifikati FAQAT CC01_ACCESS_TLS_CA dagi CA'lar bilan tekshiriladi
//     (tizim ildizlari hech qachon ishlatilmaydi), edge esa o'z klient
//     sertifikatini ko'rsatadi — AP uning Subject CN'ini allowlist bilan
//     solishtiradi va clientAuth EKU talab qiladi. TLS 1.3 majburiy.
//   - plaintext — faqat CC01_ACCESS_ADDR loopback bo'lsa (127.0.0.0/8,
//     ::1, localhost). Boshqa har qanday manzilga shifrsiz ulanish server
//     ishga tushishini to'xtatadi.
//
// Fayllar ishga tushishda bir marta o'qiladi: sertifikatni almashtirish
// (rotation) uchun edge qayta ishga tushirilishi kerak.
const (
	envAccessTLSCA         = "CC01_ACCESS_TLS_CA"
	envAccessTLSCert       = "CC01_ACCESS_TLS_CERT"
	envAccessTLSKey        = "CC01_ACCESS_TLS_KEY"
	envAccessTLSServerName = "CC01_ACCESS_TLS_SERVER_NAME"

	// envAccessTLSMin — minimal TLS versiyasi: "1.3" (sukut) yoki "1.2".
	//
	// ⚠️ "1.2" FAQAT loopback'dagi AP uchun ruxsat etiladi. Sabab: macOS'da
	// .NET server tomonda TLS 1.3 ni qo'llamaydi (Apple SecureTransport) —
	// Mac'da `dotnet run` qilingan AP faqat TLS 1.2 da gaplashadi. Prod
	// Linux'da AP TLS 1.3 ni majburlaydi va tarmoqdagi AP uchun bu
	// "pasaytirish tugmasi" umuman ishlamaydi: tarmoq orqali ketadigan
	// kanalni kimdir xato sozlama bilan zaiflashtira olmasligi kerak.
	envAccessTLSMin = "CC01_ACCESS_TLS_MIN"
)

// AccessTLSInfo — yoqilgan mTLS haqida log uchun ma'lumot.
type AccessTLSInfo struct {
	CAFile     string
	CertFile   string
	ServerName string

	// ClientCN — edge klient sertifikatining Subject CN'i (edge
	// identifikatori, AP allowlist'ida turishi kerak).
	ClientCN       string
	ClientNotAfter time.Time

	// MinVersion — "1.3" yoki (faqat loopback) "1.2".
	MinVersion string
}

// loadAccessTLS edge→AP kanali uchun mTLS sozlamasini o'qiydi va
// fayllarni darhol tekshiradi: noto'g'ri fayl server ishga tushganda
// aniqlanishi kerak, birinchi tunnel ochilganda emas.
//
// AuthMode=disabled bo'lsa chaqirilmaydi — AP'ga ulanish yo'q.
func (c *Config) loadAccessTLS() error {
	caFile := os.Getenv(envAccessTLSCA)
	certFile := os.Getenv(envAccessTLSCert)
	keyFile := os.Getenv(envAccessTLSKey)
	serverName := os.Getenv(envAccessTLSServerName)
	minVersion := os.Getenv(envAccessTLSMin)

	c.AccessTLS, c.AccessTLSInfo = nil, nil

	host, err := AccessHost(c.AccessAddr)
	if err != nil {
		return fmt.Errorf("CC01_ACCESS_ADDR noto'g'ri: %q (host:port kutilgan): %v", c.AccessAddr, err)
	}

	if caFile == "" && certFile == "" && keyFile == "" {
		for _, v := range []struct{ name, value string }{
			{envAccessTLSServerName, serverName},
			{envAccessTLSMin, minVersion},
		} {
			if v.value != "" {
				return fmt.Errorf("%s berilgan, lekin mTLS sozlanmagan: %s, %s va %s ham kerak",
					v.name, envAccessTLSCA, envAccessTLSCert, envAccessTLSKey)
			}
		}
		if !IsLoopbackHost(host) {
			return fmt.Errorf(
				"CC01_ACCESS_ADDR loopback emas va mTLS sozlanmagan (%s).\n"+
					"  Edge→access-server kanali tarmoq orqali shifrsiz ketmasligi uchun server ishga tushmadi.\n"+
					"  Yechim: %s, %s va %s ni bering (DEV_SPEC S-11),\n"+
					"  yoki access-server bir hostda bo'lsa: CC01_ACCESS_ADDR=127.0.0.1:port",
				c.AccessAddr, envAccessTLSCA, envAccessTLSCert, envAccessTLSKey)
		}
		return nil
	}

	var missing []string
	for _, v := range []struct{ name, value string }{
		{envAccessTLSCA, caFile},
		{envAccessTLSCert, certFile},
		{envAccessTLSKey, keyFile},
	} {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("mTLS chala sozlangan: %s sozlanmagan (%s, %s va %s birga berilishi shart)",
			strings.Join(missing, ", "), envAccessTLSCA, envAccessTLSCert, envAccessTLSKey)
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("%s faylini o'qib bo'lmadi: %w", envAccessTLSCA, err)
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("%s faylini o'qib bo'lmadi: %w", envAccessTLSCert, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("%s faylini o'qib bo'lmadi: %w", envAccessTLSKey, err)
	}

	if serverName == "" {
		serverName = host
	}
	tlsConfig, leaf, err := AccessClientTLS(caPEM, certPEM, keyPEM, serverName)
	if err != nil {
		return err
	}

	switch minVersion {
	case "", "1.3":
		minVersion = "1.3"
	case "1.2":
		if !IsLoopbackHost(host) {
			return fmt.Errorf(
				"%s=1.2 faqat loopback'dagi access-server uchun ruxsat etiladi (CC01_ACCESS_ADDR=%s).\n"+
					"  Tarmoq orqali kanal TLS 1.3 bilan ishlaydi; 1.2 — faqat macOS'dagi dev AP uchun.",
				envAccessTLSMin, c.AccessAddr)
		}
		tlsConfig.MinVersion = tls.VersionTLS12
	default:
		return fmt.Errorf("%s noma'lum: %q (1.3 yoki 1.2)", envAccessTLSMin, minVersion)
	}

	c.AccessTLS = tlsConfig
	c.AccessTLSInfo = &AccessTLSInfo{
		CAFile:         caFile,
		CertFile:       certFile,
		ServerName:     serverName,
		ClientCN:       leaf.Subject.CommonName,
		ClientNotAfter: leaf.NotAfter,
		MinVersion:     minVersion,
	}
	return nil
}

// AccessClientTLS edge→AP kanali uchun klient TLS sozlamasini PEM
// ma'lumotlardan quradi. Xatolar tegishli muhit o'zgaruvchisini nomlaydi.
//
//   - caPEM — AP server sertifikatini tekshiradigan YAGONA ildizlar;
//   - certPEM/keyPEM — edge klient sertifikati va kaliti (ECDSA P-256 yoki
//     RSA; PKCS#1, PKCS#8 yoki SEC 1);
//   - serverName — AP sertifikatida bo'lishi kerak bo'lgan nom (DNS SAN
//     yoki IP SAN).
//
// Qaytarilgan leaf — klient sertifikati (log uchun).
func AccessClientTLS(caPEM, certPEM, keyPEM []byte, serverName string) (*tls.Config, *x509.Certificate, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("%s: PEM formatidagi sertifikat topilmadi", envAccessTLSCA)
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%s / %s: sertifikat yoki kalit noto'g'ri (yoki bir-biriga mos emas): %w",
			envAccessTLSCert, envAccessTLSKey, err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return nil, nil, fmt.Errorf("%s: sertifikatni o'qib bo'lmadi: %w", envAccessTLSCert, err)
		}
		pair.Leaf = leaf
	}

	// AP klientni CN bo'yicha taniydi va clientAuth EKU talab qiladi —
	// bular bo'lmasa har bir chaqiruv rad etilardi. Buni ishga tushishda
	// aniq xato bilan aytish, keyin "handshake failed" ni tahlil qilishdan
	// yaxshiroq.
	if leaf.Subject.CommonName == "" {
		return nil, nil, fmt.Errorf("%s: sertifikatda Subject CN yo'q — AP edge'ni CN bo'yicha taniydi",
			envAccessTLSCert)
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return nil, nil, fmt.Errorf("%s: sertifikatda clientAuth EKU yo'q (CN=%s) — AP uni qabul qilmaydi",
			envAccessTLSCert, leaf.Subject.CommonName)
	}
	if now := time.Now(); now.After(leaf.NotAfter) {
		return nil, nil, fmt.Errorf("%s: sertifikat muddati tugagan (CN=%s, %s gacha edi)",
			envAccessTLSCert, leaf.Subject.CommonName, leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	if serverName == "" {
		return nil, nil, fmt.Errorf("%s: AP server nomi bo'sh", envAccessTLSServerName)
	}

	return &tls.Config{
		// Faqat ichki CA: tizim ildizlari (RootCAs=nil) hech qachon
		// ishlatilmaydi — aks holda istalgan ochiq CA chiqargan sertifikat
		// AP o'rnida qabul qilinardi.
		RootCAs:      roots,
		Certificates: []tls.Certificate{pair},
		ServerName:   serverName,
		// TLS 1.3 majburiy (DEV_SPEC §7.2): kanalning ikkala tomoni ham
		// bizniki, eski versiyalar bilan moslikka ehtiyoj yo'q.
		MinVersion: tls.VersionTLS13,
	}, leaf, nil
}

// AccessHost CC01_ACCESS_ADDR dan host qismini ajratadi. Manzil
// "host:port" yoki gRPC target ko'rinishida ("dns:///host:port",
// "passthrough:///host:port") bo'lishi mumkin; port majburiy.
func AccessHost(addr string) (string, error) {
	target := addr
	if i := strings.Index(target, "://"); i >= 0 {
		// scheme://[authority]/endpoint
		rest := target[i+len("://"):]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			return "", errors.New("gRPC target'da endpoint yo'q")
		}
		target = rest[j+1:]
	}

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	if host == "" {
		return "", errors.New("host bo'sh")
	}
	return host, nil
}

// IsLoopbackHost — host loopback manzilmi: 127.0.0.0/8, ::1 (IPv4-mapped
// ham) yoki "localhost". Faqat shunday manzilga shifrsiz ulanish ruxsat
// etiladi.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

// IsLoopbackAddr — CC01_ACCESS_ADDR ko'rinishidagi manzil loopback'ga
// qaraydimi. Noto'g'ri manzil — loopback emas.
func IsLoopbackAddr(addr string) bool {
	host, err := AccessHost(addr)
	return err == nil && IsLoopbackHost(host)
}
