package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// AuthMode — tunnel so'rovlari qanday avtorizatsiya qilinishi.
type AuthMode string

const (
	// AuthRequired — har bir tunnel access-server tomonidan avtorizatsiya
	// qilinadi. Standart va yagona tavsiya etiladigan rejim.
	AuthRequired AuthMode = "required"

	// AuthDisabled — avtorizatsiya o'chirilgan: har qanday token qabul
	// qilinadi, subdomain egaligi tekshirilmaydi. Faqat lokal ishlab
	// chiqish uchun; oshkora yoqilishi shart.
	AuthDisabled AuthMode = "disabled"
)

type Config struct {
	DomainName          string
	MaxConsPerTunnel    int
	EventServerPort     uint16
	PublicServerPort    uint16
	PublicServerTLSPort uint16
	TLSCertFile         string
	TLSKeyFile          string

	AuthMode      AuthMode
	AccessAddr    string
	AccessTimeout time.Duration
	AccessGrace   time.Duration
}

func (c *Config) Load() error {
	c.MaxConsPerTunnel = 24
	c.DomainName = os.Getenv("CC01_DOMAIN")

	// Portlar sozlanadigan: 80/443 imtiyoz talab qiladi, shuning uchun
	// lokal sinov va konteynerdagi port-mapping uchun ularni almashtirish
	// mumkin bo'lishi kerak.
	var err error
	if c.PublicServerPort, err = portEnv("CC01_PUBLIC_PORT", 80); err != nil {
		return err
	}
	if c.PublicServerTLSPort, err = portEnv("CC01_PUBLIC_TLS_PORT", 443); err != nil {
		return err
	}
	if c.EventServerPort, err = portEnv("CC01_EVENT_PORT", 4321); err != nil {
		return err
	}
	c.TLSKeyFile = os.Getenv("CC01_TLS_KEY")
	c.TLSCertFile = os.Getenv("CC01_TLS_CERT")

	if c.DomainName == "" {
		return errors.New("CC01_DOMAIN sozlanmagan")
	}
	if c.TLSKeyFile == "" || c.TLSCertFile == "" {
		return errors.New("CC01_TLS_KEY yoki CC01_TLS_CERT sozlanmagan")
	}

	return c.loadAuth()
}

// loadAuth avtorizatsiyani deny-by-default tamoyili bo'yicha sozlaydi
// (ARCHITECTURE.md §1.5): sukut bo'yicha ochiq qolib ketmasligi uchun
// avtorizatsiyani o'chirish OSHKORA yozilishi shart.
func (c *Config) loadAuth() error {
	c.AuthMode = AuthMode(os.Getenv("CC01_AUTH_MODE"))
	c.AccessAddr = os.Getenv("CC01_ACCESS_ADDR")

	switch c.AuthMode {
	case "":
		if c.AccessAddr == "" {
			return errors.New(
				"CC01_ACCESS_ADDR sozlanmagan.\n" +
					"  Tunnellar avtorizatsiyasiz ochilib ketmasligi uchun server ishga tushmadi.\n" +
					"  Yechim: CC01_ACCESS_ADDR=host:port (access-server ichki porti),\n" +
					"  yoki lokal sinov uchun oshkora: CC01_AUTH_MODE=disabled")
		}
		c.AuthMode = AuthRequired

	case AuthRequired:
		if c.AccessAddr == "" {
			return errors.New("CC01_AUTH_MODE=required, lekin CC01_ACCESS_ADDR sozlanmagan")
		}

	case AuthDisabled:
		// Ruxsat etilgan, lekin main.go ogohlantirish chiqaradi.

	default:
		return fmt.Errorf("CC01_AUTH_MODE noma'lum: %q (required yoki disabled)", c.AuthMode)
	}

	var err error
	if c.AccessTimeout, err = durationEnv("CC01_ACCESS_TIMEOUT", 3*time.Second); err != nil {
		return err
	}
	if c.AccessGrace, err = durationEnv("CC01_ACCESS_GRACE", 15*time.Minute); err != nil {
		return err
	}
	return nil
}

func portEnv(name string, fallback uint16) (uint16, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%s noto'g'ri port: %q", name, raw)
	}
	return uint16(value), nil
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}

	// Sof son berilgan bo'lsa — sekund deb qabul qilamiz.
	if seconds, err := strconv.Atoi(raw); err == nil {
		return time.Duration(seconds) * time.Second, nil
	}

	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s noto'g'ri formatda: %q", name, raw)
	}
	return value, nil
}
