// Package cptls Control Plane kanalining TLS sozlamalarini beradi.
//
// Nega alohida paket: sertifikat yaratish CP tomonida, pin tekshiruvi
// esa demon tomonida kerak, va ikkalasi ham AYNAN bir xil pin
// hisoblashi shart. Bitta joyda turgani ularning ajralib ketishiga
// yo'l qo'ymaydi.
package cptls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"time"
)

// PinPrefix — pin satrining old qo'shimchasi. Format oshkora
// yozilgani muhim: keyin boshqa xesh algoritmiga o'tilsa, eski
// pinlar jimgina noto'g'ri talqin qilinmaydi.
const PinPrefix = "sha256/"

// certValidity — self-signed sertifikatning amal qilish muddati.
//
// Uzoq: pin sertifikatning OCHIQ KALITIGA bog'langan, muddatiga emas.
// Sertifikat muddati tugasa, pin o'zgarmagan bo'lsa ham ulanish
// uziladi va bu operator uchun kutilmagan nosozlik bo'lardi.
const certValidity = 10 * 365 * 24 * time.Hour

// Pin — sertifikatning ochiq kaliti (SPKI) ustidan hisoblangan
// barmoq izi.
//
// Sertifikatning o'zi emas, AYNAN SPKI xeshlanadi: shunda sertifikat
// yangilanganda (masalan muddati uzaytirilganda) kalit o'zgarmasa pin
// ham o'zgarmaydi va nodelarni qayta sozlash kerak bo'lmaydi. Bu
// HPKP va gRPC klientlaridagi odatiy amaliyot.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return PinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// GenerateSelfSigned CP uchun yangi self-signed sertifikat yaratadi.
//
// Ed25519: kalit kichik, imzo tez va TLS 1.3 uni to'liq qo'llaydi.
//
// `hosts` — sertifikatga yoziladigan nomlar va IP'lar. Pin
// tekshiruvida ular ishlatilmaydi, lekin standart TLS klientlari
// (masalan `grpcurl`) uchun kerak.
func GenerateSelfSigned(hosts []string) (tls.Certificate, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cptls: kalit yaratish: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cptls: seriya raqami: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "cc01 control plane"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	for _, host := range hosts {
		if addr, err := netip.ParseAddr(host); err == nil {
			template.IPAddresses = append(template.IPAddresses, net.IP(addr.AsSlice()))
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cptls: sertifikat yaratish: %w", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("cptls: sertifikatni o'qish: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  private,
		Leaf:        leaf,
	}, nil
}

// ServerConfig CP uchun TLS sozlamasi.
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TLS 1.3 majburiy (DEV_SPEC §7.2 S-3). Eski versiyalarga
		// tushishga ruxsat bermaymiz: bu kanal faqat bizning
		// klientlarimizga xizmat qiladi, ya'ni moslik uchun
		// chegirma qilishning hojati yo'q.
		MinVersion: tls.VersionTLS13,
	}
}

// Encode sertifikat va kalitni PEM ko'rinishida beradi (saqlash uchun).
func Encode(cert tls.Certificate) (certPEM, keyPEM []byte, err error) {
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cptls: kalitni kodlash: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	return certPEM, keyPEM, nil
}
