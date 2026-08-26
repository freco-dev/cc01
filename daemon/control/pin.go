package control

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// PinPrefix — pin satrining old qo'shimchasi.
//
// Format CP bilan umumiy shartnoma:
//
//	sha256/<base64(SHA-256(sertifikat SPKI))>
//
// Xesh AYNAN SPKI (ochiq kalit) ustidan olinadi, sertifikatning o'zi
// ustidan emas: shunda sertifikat yangilanganda kalit o'zgarmasa pin
// ham o'zgarmaydi va nodelarni qayta sozlash kerak bo'lmaydi.
//
// Prefiks oshkora yozilgan: keyin boshqa algoritmga o'tilsa, eski
// pinlar jimgina noto'g'ri talqin qilinmaydi.
//
// ⚠️ Bu format `control/cptls` da ham takrorlanadi (modullar alohida).
// Ikkalasida ham bir xil sinov vektori bor — ular ajralib ketsa
// testlar yiqiladi.
const PinPrefix = "sha256/"

// ErrPinMismatch — server sertifikati kutilgan pinga mos kelmadi.
var ErrPinMismatch = errors.New("control: CP sertifikati pinga mos emas")

// verifyPin berilgan pinlardan biriga mos keladigan sertifikatni
// qidiradi.
//
// Bir nechta pin qabul qilinadi: kalit almashtirilayotganda eski va
// yangisi bir vaqtda amal qilishi kerak, aks holda almashtirish
// butun parkni bir zumda uzib qo'yardi.
func verifyPin(rawCerts [][]byte, pins []string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("%w: sertifikat berilmadi", ErrPinMismatch)
	}

	// Faqat leaf tekshiriladi. Oraliq sertifikatga pin qo'yish
	// zanjir o'zgarganda uzilishga olib keladi va hech qanday
	// qo'shimcha kafolat bermaydi.
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("%w: sertifikatni o'qib bo'lmadi: %v", ErrPinMismatch, err)
	}

	actual := SPKIPin(cert)

	for _, expected := range pins {
		// Doimiy vaqt: pin sir emas, lekin solishtirishni bir xil
		// uslubda qilgan yaxshi — keyin bu kod sirlarga ham
		// ko'chirilishi mumkin.
		if subtle.ConstantTimeCompare([]byte(actual), []byte(strings.TrimSpace(expected))) == 1 {
			return nil
		}
	}

	return fmt.Errorf("%w\n  kutilgan: %s\n  olingan:  %s",
		ErrPinMismatch, strings.Join(pins, ", "), actual)
}

// SPKIPin sertifikatning ochiq kaliti ustidan pin hisoblaydi.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return PinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// tlsConfig CP ga ulanish uchun TLS sozlamasini yasaydi.
//
// Pin berilgan bo'lsa standart zanjir tekshiruvi O'CHIRILADI va uning
// o'rniga pin qo'yiladi. Sabab: CP sertifikati self-signed bo'lishi
// mumkin va uni ommaviy CA tasdiqlamaydi. Pin esa kuchliroq kafolat
// beradi — u aniq bitta kalitga bog'lanadi, ya'ni buzilgan yoki
// aldangan CA ham yordam bermaydi.
func tlsConfig(serverName string, pins []string) *tls.Config {
	cfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	}

	if len(pins) == 0 {
		return cfg
	}

	cfg.InsecureSkipVerify = true // pin bilan almashtiriladi (quyida)
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return verifyPin(rawCerts, pins)
	}
	return cfg
}
