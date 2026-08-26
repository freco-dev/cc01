package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/freco-dev/cc01/control/cptls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// serverOptions kanal himoyasini tanlaydi.
//
// Standart — TLS 1.3 self-signed sertifikat bilan. Bu kanal orqali
// butun NetworkMap (kim tarmoqda, qaysi manzilda, qaysi kalit bilan)
// va nodelarning autentifikatsiya tokeni o'tadi, ya'ni uni ochiq
// qoldirish tarmoqni kuzatuvchiga to'liq ko'rsatib qo'yadi.
//
// Self-signed sertifikat ommaviy CA tomonidan tasdiqlanmaydi —
// shuning uchun nodelar PIN bilan ulanadi. Pin ishga tushishda
// chiqariladi.
func serverOptions(cfg runConfig, logger *slog.Logger) ([]grpc.ServerOption, error) {
	if cfg.insecure {
		logger.Warn("CP KANALI SHIFRLANMAGAN — NetworkMap va tokenlar ochiq matnda uzatiladi; " +
			"faqat lokal sinov uchun")
		return nil, nil
	}

	cert, err := loadOrGenerate(cfg, logger)
	if err != nil {
		return nil, err
	}

	logger.Info("CP sertifikati tayyor", "pin", cptls.Pin(cert.Leaf))
	fmt.Fprintf(os.Stderr, "\n  Nodelar shu pin bilan ulanadi:\n      -cp-pin %s\n\n",
		cptls.Pin(cert.Leaf))

	return []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(cptls.ServerConfig(cert))),
	}, nil
}

// loadOrGenerate sertifikatni fayldan o'qiydi yoki yangisini yaratadi.
func loadOrGenerate(cfg runConfig, logger *slog.Logger) (tls.Certificate, error) {
	if cfg.tlsCert != "" && cfg.tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.tlsCert, cfg.tlsKey)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("sertifikatni o'qish: %w", err)
		}
		return cert, nil
	}

	// Sertifikat berilmagan — yangisini yaratamiz.
	//
	// ⚠️ U jarayon xotirasida yashaydi: qayta ishga tushirilganda
	// kalit ham, pin ham o'zgaradi va hamma nodelarni qayta sozlash
	// kerak bo'ladi. Ishlab chiqarishda -tls-cert/-tls-key bilan
	// saqlangan sertifikat berilishi shart.
	hosts := cfg.tlsHosts
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}

	cert, err := cptls.GenerateSelfSigned(hosts)
	if err != nil {
		return tls.Certificate{}, err
	}

	logger.Warn("vaqtinchalik sertifikat yaratildi — qayta ishga tushirilsa PIN O'ZGARADI",
		"hosts", strings.Join(hosts, ","),
		"maslahat", "ishlab chiqarish uchun: -tls-cert va -tls-key")

	return cert, nil
}
