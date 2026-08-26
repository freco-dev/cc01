// Package nodecert nodening TLS klient sertifikatini boshqaradi.
//
// # Nima uchun kerak
//
// CP ga ulanishda node oldindan kelishilgan token bilan tanitilardi.
// Token UMUMIY sir: u hamma nodeda bir xil, ya'ni bitta node buzilsa
// o'sha token bilan boshqa node ham ro'yxatdan o'ta oladi.
//
// Sertifikat esa faqat SHU nodeda bo'ladi. Token endi bir martalik
// ro'yxatga olish uchun ishlatiladi; undan keyin nodeni sertifikati
// tanitadi. Ya'ni o'g'irlangan token bilan YANGI node qo'shish
// mumkin, lekin mavjud nodening o'rniga o'tib bo'lmaydi.
//
// # Nega Ed25519, Noise kaliti emas
//
// Nodening asosiy identifikatori — Curve25519 (X25519) Noise kaliti.
// U ECDH uchun, imzo uchun emas; TLS klient sertifikati esa imzo
// talab qiladi. X25519 dan Ed25519 ga xavfsiz o'tish standart emas,
// shuning uchun alohida kalit yaratiladi va u node_id ga CP tomonida
// bog'lanadi.
package nodecert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	// CertFile, KeyFile — holat papkasidagi fayl nomlari.
	CertFile = "node.crt"
	KeyFile  = "node.key"

	// keyMode — kalit FAQAT egasiga o'qilishi kerak. Bu fayl
	// nodening CP oldidagi yagona dalili.
	keyMode = 0o600

	// validity — sertifikat muddati.
	//
	// Uzoq: bog'lanish sertifikatning OCHIQ KALITIGA qo'yiladi,
	// muddatiga emas. Muddat tugasa node CP ga kira olmay qolardi
	// va buni tiklash uchun qo'lda aralashuv kerak bo'lardi.
	validity = 10 * 365 * 24 * time.Hour
)

// PinPrefix — sertifikat barmoq izining old qo'shimchasi.
//
// Format CP bilan umumiy: sha256/<base64(SHA-256(SPKI))>. U CP
// kanalining pinlari bilan bir xil, shuning uchun bitta tushuncha
// ikkala yo'nalishda ham ishlaydi.
const PinPrefix = "sha256/"

// Pin sertifikatning ochiq kaliti ustidan barmoq izi hisoblaydi.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return PinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// Load sertifikatni papkadan o'qiydi, bo'lmasa yangisini yaratadi.
//
// Yaratish IDEMPOTENT emas: har chaqiruvda yangi kalit chiqadi.
// Shuning uchun mavjud fayl har doim ustunlik qiladi — aks holda
// demon qayta ishga tushganda o'z identifikatorini yo'qotardi va
// CP uni begona deb rad etardi.
func Load(dir string) (tls.Certificate, error) {
	if dir == "" {
		return tls.Certificate{}, errors.New("nodecert: papka berilmagan")
	}

	certPath := filepath.Join(dir, CertFile)
	keyPath := filepath.Join(dir, KeyFile)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		if cert.Leaf == nil {
			// Go 1.23 gacha Leaf to'ldirilmasdi; u har ulanishda
			// qayta parse qilinmasligi uchun kerak.
			leaf, parseErr := x509.ParseCertificate(cert.Certificate[0])
			if parseErr != nil {
				return tls.Certificate{}, fmt.Errorf("nodecert: sertifikatni o'qish: %w", parseErr)
			}
			cert.Leaf = leaf
		}
		return cert, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, fmt.Errorf("nodecert: mavjud sertifikat o'qilmadi: %w", err)
	}

	return create(dir, certPath, keyPath)
}

func create(dir, certPath, keyPath string) (tls.Certificate, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("nodecert: papka yaratish: %w", err)
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("nodecert: kalit yaratish: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("nodecert: seriya raqami: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "cc01 node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("nodecert: sertifikat yaratish: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("nodecert: kalitni kodlash: %w", err)
	}

	// Kalit AVVAL yoziladi va faqat undan keyin sertifikat.
	//
	// Teskari tartibda demon yozish orasida to'xtasa, sertifikat
	// kalitsiz qolardi — keyingi Load esa "mavjud" deb topib,
	// o'qishda yiqilardi va node umuman ko'tarilmasdi.
	if err := writeFile(keyPath, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), keyMode); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeFile(certPath, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("nodecert: sertifikatni o'qish: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  private,
		Leaf:        leaf,
	}, nil
}

// writeFile faylni atomik yozadi: avval vaqtinchalik faylga, keyin
// joyiga ko'chiradi. Yarim yozilgan kalit fayli qolmasligi kerak.
func writeFile(path string, data []byte, mode os.FileMode) error {
	temp := path + ".tmp"

	if err := os.WriteFile(temp, data, mode); err != nil {
		return fmt.Errorf("nodecert: %s yozish: %w", path, err)
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("nodecert: %s ko'chirish: %w", path, err)
	}
	return nil
}
