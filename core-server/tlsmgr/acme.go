package tlsmgr

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
)

// LetsEncryptStaging — sinov uchun ACME katalogi.
//
// Ishlab chiqarish katalogining limitlari qattiq (haftasiga 50
// sertifikat/domen) va ularni sinov paytida yoqib yuborish oson.
const LetsEncryptStaging = certmagic.LetsEncryptStagingCA

// ACMEOptions — ACME chiqaruvchisining sozlamalari.
type ACMEOptions struct {
	// Email — ACME hisobi uchun. Let's Encrypt uni sertifikat
	// muddati tugayotganda ogohlantirish yuborish uchun ishlatadi.
	Email string

	// Directory — sertifikatlar va hisob kalitlari saqlanadigan
	// papka.
	//
	// DOIMIY diskda bo'lishi shart: konteyner qayta ishga
	// tushganda bo'sh papka hamma sertifikatni qaytadan
	// chiqarishga majbur qilardi va bu limitga urilishning eng
	// tez yo'li.
	Directory string

	// CA — ACME katalogi manzili. Bo'sh bo'lsa Let's Encrypt
	// ishlab chiqarish katalogi.
	CA string

	// Decide — bu nomga sertifikat chiqarish mumkinmi.
	//
	// Resolver ham shu tekshiruvni qiladi, lekin bu yerda ham
	// kerak: certmagic sertifikatni fon rejimida ham yangilaydi
	// va o'shanda resolver oralig'ida turmaydi.
	Decide KnownFunc

	Logger *slog.Logger
}

// ACME — certmagic ustidagi ingichka qatlam.
type ACME struct {
	config *certmagic.Config
	log    *slog.Logger
}

// NewACME ACME chiqaruvchisini quradi.
func NewACME(opts ACMEOptions) (*ACME, error) {
	if strings.TrimSpace(opts.Email) == "" {
		return nil, errors.New("tlsmgr: ACME uchun email berilmagan")
	}
	if strings.TrimSpace(opts.Directory) == "" {
		return nil, errors.New("tlsmgr: ACME uchun saqlash papkasi berilmagan")
	}
	if opts.Decide == nil {
		// Qaror funksiyasisiz certmagic HAR QANDAY nomga
		// sertifikat chiqarardi — ACME limitini yoqib yuborish
		// uchun shundan oson yo'l yo'q.
		return nil, errors.New("tlsmgr: ACME uchun qaror funksiyasi berilmagan")
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	acme := &ACME{log: logger}

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return acme.config, nil
		},
	})

	config := certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: opts.Directory},
		OnDemand: &certmagic.OnDemandConfig{
			DecisionFunc: func(_ context.Context, name string) error {
				if opts.Decide(strings.ToLower(name)) {
					return nil
				}
				return fmt.Errorf("%w: %s", ErrUnknownName, name)
			},
		},
	})

	config.Issuers = []certmagic.Issuer{
		certmagic.NewACMEIssuer(config, certmagic.ACMEIssuer{
			CA:     opts.CA,
			Email:  opts.Email,
			Agreed: true,
		}),
	}

	acme.config = config
	return acme, nil
}

// Certificate — Issuer interfeysi.
func (a *ACME) Certificate(ctx context.Context, name string) (*tls.Certificate, error) {
	return a.config.GetCertificateWithContext(ctx, &tls.ClientHelloInfo{ServerName: name})
}

// ChallengeCertificate TLS-ALPN-01 sinovi uchun sertifikat beradi.
//
// Sinov AYNAN 443-portda, oddiy trafik bilan bir listener'da
// javob topishi kerak — ACME serveri boshqa portga bormaydi.
// Shuning uchun u resolver'dan OLDIN tekshiriladi: resolver bu
// nomni bilmasligi mumkin va qo'l siqishini uzib, sinovni
// muvaffaqiyatsiz qilardi.
func (a *ACME) ChallengeCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, bool) {
	if !slices.Contains(hello.SupportedProtos, acmez.ACMETLS1Protocol) {
		return nil, false
	}

	cert, err := a.config.GetCertificate(hello)
	if err != nil {
		a.log.Warn("ACME sinovi uchun sertifikat berilmadi",
			"nom", hello.ServerName, "err", err)
		return nil, false
	}
	return cert, true
}

// TLSConfig ACME sinovlarini ham, oddiy trafikni ham qo'llaydigan
// sozlamani quradi.
//
// `NextProtos` ga `acme-tls/1` QO'SHILADI: usiz ACME serveri
// sinovni boshlay olmaydi va sertifikat hech qachon chiqmaydi.
func TLSConfig(resolver *Resolver, acme *ACME, protos ...string) *tls.Config {
	get := resolver.GetCertificate

	if acme != nil {
		get = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cert, ok := acme.ChallengeCertificate(hello); ok {
				return cert, nil
			}
			return resolver.GetCertificate(hello)
		}
		protos = append(protos, acmez.ACMETLS1Protocol)
	}

	return &tls.Config{
		GetCertificate: get,
		NextProtos:     protos,
		MinVersion:     tls.VersionTLS12,
	}
}
