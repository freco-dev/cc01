package config

import (
	"crypto/tls"
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

	// ACME — custom domainlar uchun avtomatik sertifikat.
	//
	// ⚠️ Wildcard sertifikat bunga KIRMAYDI: `*.cc01.uz` ni olish
	// uchun DNS-01 sinovi kerak, u esa DNS provayderining
	// kalitlarini talab qiladi. Shuning uchun wildcard operator
	// tomonidan fayl sifatida beriladi, ACME esa faqat mijoz
	// domenlariga ishlaydi (ular HTTP-01/TLS-ALPN-01 bilan
	// hal bo'ladi).
	ACMEEmail     string
	ACMEDirectory string
	ACMECA        string

	AuthMode      AuthMode
	AccessAddr    string
	AccessTimeout time.Duration
	AccessGrace   time.Duration

	// AccessTLS — edge→AP kanalining mTLS sozlamasi (accesstls.go). nil —
	// shifrsiz, faqat loopback CC01_ACCESS_ADDR uchun ruxsat etiladi.
	// AuthMode=disabled bo'lsa doim nil. Ishga tushishda bir marta
	// o'qiladi: sertifikat almashtirilsa edge qayta ishga tushiriladi.
	AccessTLS *tls.Config
	// AccessTLSInfo — AccessTLS haqida log uchun ma'lumot (nil — shifrsiz).
	AccessTLSInfo *AccessTLSInfo

	// AccessRenew — ochiq tunnel ruxsatini AP'da qayta tekshirish oralig'i
	// (lease yangilanishi). 0 — yangilash o'chirilgan (kill switch): ochiq
	// tunnel ochilishdagi limitlar bilan qoladi. AuthMode=disabled bo'lsa
	// doim 0.
	AccessRenew time.Duration

	// AccessRenewDeny — yangilashda qat'iy rad javobi kelganda nima
	// qilinadi: tunnel yopiladi (close) yoki faqat log'ga yoziladi (log —
	// dry run, rollout uchun).
	AccessRenewDeny RenewDenyMode

	// UsageInterval — foydalanish oynasi uzunligi va AP'ga hisobot
	// oralig'i (CC01_USAGE_INTERVAL). Oynalar devor soatiga tekislangan
	// (unix vaqt UsageInterval ga karrali). 0 — hisobot o'chirilgan.
	// AuthMode=disabled bo'lsa doim 0.
	UsageInterval time.Duration
}

// RenewDenyMode — yangilashdagi rad javobiga munosabat.
type RenewDenyMode string

const (
	// RenewDenyClose — allowlist'dagi rad javobi ochiq tunnelni yopadi.
	// Standart.
	RenewDenyClose RenewDenyMode = "close"

	// RenewDenyLog — rad javobi faqat log'ga yoziladi, tunnel yopilmaydi
	// (dry run).
	RenewDenyLog RenewDenyMode = "log"
)

const (
	// DefaultAccessTimeout — AP chaqirig'i taymauti (CC01_ACCESS_TIMEOUT).
	DefaultAccessTimeout = 3 * time.Second

	// DefaultAccessRenew — ochiq tunnel yangilanish oralig'i
	// (CC01_ACCESS_RENEW). Tarif o'zgarishi edge'ga ≤ R + taymaut =
	// 30 + 3 = 33 s ichida yetib boradi (AP yiqilib qaytgandan keyin —
	// ≤ 6 + 30 + 3 = 39 s).
	DefaultAccessRenew = 30 * time.Second

	// MinAccessRenew va MaxAccessRenew — CC01_ACCESS_RENEW ning ruxsat
	// etilgan oralig'i (0 dan tashqari). Pastki chegara AP'ni ortiqcha
	// yuklamaslik uchun. Yuqori chegaraning o'zi yetarli emas: 60 s
	// kafolati CC01_ACCESS_TIMEOUT bilan birga tekshiriladi (AccessSLO).
	MinAccessRenew = 1 * time.Second
	MaxAccessRenew = 50 * time.Second

	// AccessReconnectMax — AP qayta erishiladigan bo'lgandan edge→AP gRPC
	// kanali qayta ulanguncha eng uzoq kutish (access.Dial'dagi cheklangan
	// backoff: MinConnectTimeout 3 s + MaxDelay 2 s·1.2). AP yiqilib
	// qaytgandan keyingi eng yomon holat shu qadar uzayadi.
	AccessReconnectMax = 6 * time.Second

	// AccessSLO — AP'dagi o'zgarish (tarif, bekor qilish, to'xtatish) ochiq
	// tunnelga yetib borishining kafolatlangan chegarasi (DEV_SPEC §8).
	// Eng yomon holat: AccessReconnectMax + R + CC01_ACCESS_TIMEOUT,
	// R ≤ CC01_ACCESS_RENEW. Bu yig'indi undan QAT'IY kichik bo'lishi shart,
	// aks holda server ishga tushmaydi.
	AccessSLO = 60 * time.Second

	// DefaultUsageInterval — foydalanish oynasi (CC01_USAGE_INTERVAL).
	DefaultUsageInterval = 60 * time.Second

	// MinUsageInterval va MaxUsageInterval — CC01_USAGE_INTERVAL ning
	// ruxsat etilgan oralig'i (0 dan tashqari). Pastki chegara AP'ni har
	// tunnel uchun juda ko'p oyna bilan yuklamaslik uchun, yuqorisi —
	// edge qulaganda yo'qoladigan ma'lumot (navbat xotirada) cheklangan
	// bo'lishi uchun.
	MinUsageInterval = 5 * time.Second
	MaxUsageInterval = 300 * time.Second
)

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

	if err := c.loadACME(); err != nil {
		return err
	}
	return c.loadAuth()
}

// ACMEEnabled — custom domainlarga avtomatik sertifikat yoqilganmi.
func (c *Config) ACMEEnabled() bool { return c.ACMEEmail != "" }

// loadACME ACME sozlamalarini o'qiydi.
//
// Email berilmasa ACME O'CHIQ qoladi va custom domainlar HTTPS
// ololmaydi. Buni jimgina yoqib qo'ymaymiz: ACME haqiqiy tashqi
// xizmatga murojaat qiladi va uning limitlari bor.
func (c *Config) loadACME() error {
	c.ACMEEmail = os.Getenv("CC01_ACME_EMAIL")
	if c.ACMEEmail == "" {
		return nil
	}

	c.ACMEDirectory = os.Getenv("CC01_ACME_DIR")
	if c.ACMEDirectory == "" {
		return errors.New(
			"CC01_ACME_EMAIL berilgan, lekin CC01_ACME_DIR sozlanmagan.\n" +
				"  Sertifikatlar DOIMIY diskda saqlanishi shart: bo'sh papka\n" +
				"  har qayta ishga tushishda hamma sertifikatni qaytadan\n" +
				"  chiqartirib, ACME limitiga urardi.")
	}

	// Sinov katalogi qisqa yozuv bilan tanlanadi: to'liq URL ni
	// qo'lda yozishda xato qilish oson va xato ishlab chiqarish
	// katalogiga urib qo'yardi.
	switch ca := os.Getenv("CC01_ACME_CA"); ca {
	case "", "production":
		c.ACMECA = ""
	case "staging":
		c.ACMECA = acmeStagingCA
	default:
		c.ACMECA = ca
	}

	return nil
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

	// Avtorizatsiya o'chirilgan rejimda AP'ga ulanish yo'q — TLS
	// sozlamalari e'tiborsiz qoldiriladi.
	if c.AuthMode != AuthDisabled {
		if err := c.loadAccessTLS(); err != nil {
			return err
		}
	}

	var err error
	if c.AccessTimeout, err = durationEnv("CC01_ACCESS_TIMEOUT", DefaultAccessTimeout); err != nil {
		return err
	}
	if c.AccessTimeout <= 0 {
		return fmt.Errorf("CC01_ACCESS_TIMEOUT=%s ruxsat etilmagan: musbat bo'lishi kerak", c.AccessTimeout)
	}
	if c.AccessGrace, err = durationEnv("CC01_ACCESS_GRACE", 15*time.Minute); err != nil {
		return err
	}
	if err := c.loadRenew(); err != nil {
		return err
	}
	return c.loadUsage()
}

// loadUsage foydalanish hisoboti sozlamasini o'qiydi.
//
// Oraliq butun sekund bo'lishi shart: oyna chegaralari unix sekundda
// yuboriladi va devor soatiga tekislanadi (unix vaqt oraliqqa karrali).
func (c *Config) loadUsage() error {
	var err error
	if c.UsageInterval, err = durationEnv("CC01_USAGE_INTERVAL", DefaultUsageInterval); err != nil {
		return err
	}
	if c.UsageInterval != 0 {
		if c.UsageInterval < MinUsageInterval || c.UsageInterval > MaxUsageInterval {
			return fmt.Errorf(
				"CC01_USAGE_INTERVAL=%s ruxsat etilmagan: 0 (o'chirish) yoki %s..%s bo'lishi kerak",
				c.UsageInterval, MinUsageInterval, MaxUsageInterval)
		}
		if c.UsageInterval%time.Second != 0 {
			return fmt.Errorf(
				"CC01_USAGE_INTERVAL=%s ruxsat etilmagan: butun sekund bo'lishi kerak", c.UsageInterval)
		}
	}

	// Avtorizatsiya o'chirilgan rejimda hisobot qabul qiladigan AP yo'q.
	if c.AuthMode == AuthDisabled {
		c.UsageInterval = 0
	}
	return nil
}

// loadRenew ochiq tunnel yangilanishi sozlamalarini o'qiydi.
//
// ⚠️ Oraliq cheklangan: AP'dagi o'zgarish ochiq tunnelga ≤ R + taymaut
// ichida (AP yiqilib qaytgandan keyin — ≤ AccessReconnectMax + R + taymaut)
// yetib boradi va bu 60 s dan oshmasligi kerak. Shuning uchun kafolatni
// buzadigan CC01_ACCESS_RENEW va CC01_ACCESS_TIMEOUT jimgina qabul
// qilinmaydi — server ishga tushmaydi.
func (c *Config) loadRenew() error {
	var err error
	if c.AccessRenew, err = durationEnv("CC01_ACCESS_RENEW", DefaultAccessRenew); err != nil {
		return err
	}
	if c.AccessRenew != 0 && (c.AccessRenew < MinAccessRenew || c.AccessRenew > MaxAccessRenew) {
		return fmt.Errorf(
			"CC01_ACCESS_RENEW=%s ruxsat etilmagan: 0 (o'chirish) yoki %s..%s bo'lishi kerak "+
				"— aks holda 60 s kafolati buziladi", c.AccessRenew, MinAccessRenew, MaxAccessRenew)
	}

	switch mode := RenewDenyMode(os.Getenv("CC01_ACCESS_RENEW_DENY")); mode {
	case "", RenewDenyClose:
		c.AccessRenewDeny = RenewDenyClose
	case RenewDenyLog:
		c.AccessRenewDeny = RenewDenyLog
	default:
		return fmt.Errorf("CC01_ACCESS_RENEW_DENY noma'lum: %q (close yoki log)", mode)
	}

	// Avtorizatsiya o'chirilgan rejimda yangilaydigan AP yo'q.
	if c.AuthMode == AuthDisabled {
		c.AccessRenew = 0
	}

	if c.AccessRenew != 0 {
		if worst := AccessReconnectMax + c.AccessRenew + c.AccessTimeout; worst >= AccessSLO {
			return fmt.Errorf(
				"CC01_ACCESS_RENEW=%s va CC01_ACCESS_TIMEOUT=%s birga ruxsat etilmagan: "+
					"eng yomon holat %s (qayta ulanish) + %s + %s = %s, %s dan kichik bo'lishi kerak "+
					"— oraliqni yoki taymautni kamaytiring",
				c.AccessRenew, c.AccessTimeout,
				AccessReconnectMax, c.AccessRenew, c.AccessTimeout, worst, AccessSLO)
		}
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
