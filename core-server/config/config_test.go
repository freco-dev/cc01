package config

import (
	"strings"
	"testing"
	"time"
)

// setBaseEnv majburiy sozlamalarni qo'yadi (avtorizatsiyadan tashqari).
func setBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CC01_DOMAIN", "cc01.site")
	t.Setenv("CC01_TLS_KEY", "key.pem")
	t.Setenv("CC01_TLS_CERT", "cert.pem")
	clearAccessTLSEnv(t)
}

// clearAccessTLSEnv edge→AP mTLS o'zgaruvchilarini bo'shatadi — testlar
// ishlab chiquvchi muhitidagi qiymatlarga bog'liq bo'lmasligi uchun.
func clearAccessTLSEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"CC01_ACCESS_TLS_CA", "CC01_ACCESS_TLS_CERT",
		"CC01_ACCESS_TLS_KEY", "CC01_ACCESS_TLS_SERVER_NAME",
	} {
		t.Setenv(name, "")
	}
}

func TestLoad_WithAccessAddr(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("CC01_ACCESS_ADDR", "127.0.0.1:5081")

	var conf Config
	if err := conf.Load(); err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}

	if conf.AuthMode != AuthRequired {
		t.Errorf("AuthMode: %q kutilgan, %q olindi", AuthRequired, conf.AuthMode)
	}
	if conf.AccessGrace != 15*time.Minute {
		t.Errorf("AccessGrace: 15m kutilgan, %s olindi", conf.AccessGrace)
	}
	if conf.AccessTimeout != 3*time.Second {
		t.Errorf("AccessTimeout: 3s kutilgan, %s olindi", conf.AccessTimeout)
	}
}

// Deny-by-default: avtorizatsiya sozlanmagan bo'lsa server ishga
// tushmasligi kerak (ARCHITECTURE.md §1.5).
func TestLoad_RefusesWhenAuthNotConfigured(t *testing.T) {
	setBaseEnv(t)

	var conf Config
	err := conf.Load()
	if err == nil {
		t.Fatal("xato kutilgan edi: avtorizatsiya sozlanmagan")
	}
	if !strings.Contains(err.Error(), "CC01_ACCESS_ADDR") {
		t.Errorf("xato CC01_ACCESS_ADDR ni zikr qilishi kerak, olindi: %v", err)
	}
	if !strings.Contains(err.Error(), "CC01_AUTH_MODE=disabled") {
		t.Errorf("xato yechimni ko'rsatishi kerak, olindi: %v", err)
	}
}

func TestLoad_AuthDisabledIsExplicit(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("CC01_AUTH_MODE", "disabled")

	var conf Config
	if err := conf.Load(); err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}
	if conf.AuthMode != AuthDisabled {
		t.Errorf("AuthMode: %q olindi", conf.AuthMode)
	}
}

func TestLoad_RequiredWithoutAddrFails(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("CC01_AUTH_MODE", "required")

	var conf Config
	if err := conf.Load(); err == nil {
		t.Fatal("xato kutilgan edi")
	}
}

func TestLoad_UnknownAuthModeFails(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("CC01_AUTH_MODE", "maybe")

	var conf Config
	err := conf.Load()
	if err == nil {
		t.Fatal("xato kutilgan edi")
	}
	if !strings.Contains(err.Error(), "maybe") {
		t.Errorf("xato qiymatni ko'rsatishi kerak, olindi: %v", err)
	}
}

func TestLoad_MissingRequiredEnv(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantSub string
	}{
		{
			name:    "domain yo'q",
			env:     map[string]string{"CC01_TLS_KEY": "k", "CC01_TLS_CERT": "c"},
			wantSub: "CC01_DOMAIN",
		},
		{
			name:    "TLS kalit yo'q",
			env:     map[string]string{"CC01_DOMAIN": "cc01.site", "CC01_TLS_CERT": "c"},
			wantSub: "CC01_TLS_KEY",
		},
		{
			name:    "TLS sertifikat yo'q",
			env:     map[string]string{"CC01_DOMAIN": "cc01.site", "CC01_TLS_KEY": "k"},
			wantSub: "CC01_TLS_CERT",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			t.Setenv("CC01_AUTH_MODE", "disabled")

			var conf Config
			err := conf.Load()
			if err == nil {
				t.Fatal("xato kutilgan edi")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("%q kutilgan, olindi: %v", tc.wantSub, err)
			}
		})
	}
}

func TestDurationEnv(t *testing.T) {
	cases := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"", 15 * time.Minute, false},
		{"30", 30 * time.Second, false}, // sof son — sekund
		{"90s", 90 * time.Second, false},
		{"2m", 2 * time.Minute, false},
		{"tez", 0, true},
	}

	for _, tc := range cases {
		t.Run("raw="+tc.raw, func(t *testing.T) {
			t.Setenv("CC01_TEST_DURATION", tc.raw)

			got, err := durationEnv("CC01_TEST_DURATION", 15*time.Minute)
			if tc.wantErr {
				if err == nil {
					t.Fatal("xato kutilgan edi")
				}
				return
			}
			if err != nil {
				t.Fatalf("kutilmagan xato: %v", err)
			}
			if got != tc.want {
				t.Errorf("%s kutilgan, %s olindi", tc.want, got)
			}
		})
	}
}

// ── ACME ───────────────────────────────────────────────────────

func TestConfig_ACMEDisabledByDefault(t *testing.T) {
	cfg := loadWith(t, map[string]string{})

	if cfg.ACMEEnabled() {
		t.Error("ACME sukut bo'yicha yoqilgan")
	}
}

// Doimiy papkasiz ACME har qayta ishga tushishda hamma
// sertifikatni qaytadan chiqartirib, limitga urardi.
func TestConfig_ACMERequiresDirectory(t *testing.T) {
	if _, err := loadRaw(t, map[string]string{
		"CC01_ACME_EMAIL": "admin@cc01.uz",
	}); err == nil {
		t.Error("papkasiz ACME qabul qilindi")
	}
}

// Sinov katalogini qisqa yozuv bilan tanlash: to'liq URL ni qo'lda
// yozishda xato qilish oson va u ishlab chiqarish katalogiga urib
// qo'yardi.
func TestConfig_ACMEStagingShorthand(t *testing.T) {
	cfg := loadWith(t, map[string]string{
		"CC01_ACME_EMAIL": "admin@cc01.uz",
		"CC01_ACME_DIR":   t.TempDir(),
		"CC01_ACME_CA":    "staging",
	})

	if !cfg.ACMEEnabled() {
		t.Fatal("ACME yoqilmadi")
	}
	if cfg.ACMECA == "" || !strings.Contains(cfg.ACMECA, "staging") {
		t.Errorf("sinov katalogi tanlanmadi: %q", cfg.ACMECA)
	}
}

func TestConfig_ACMEProductionIsDefault(t *testing.T) {
	for _, value := range []string{"", "production"} {
		cfg := loadWith(t, map[string]string{
			"CC01_ACME_EMAIL": "admin@cc01.uz",
			"CC01_ACME_DIR":   t.TempDir(),
			"CC01_ACME_CA":    value,
		})
		if cfg.ACMECA != "" {
			t.Errorf("CC01_ACME_CA=%q → %q, bo'sh kutilgan edi", value, cfg.ACMECA)
		}
	}
}

func TestConfig_ACMEAcceptsCustomCA(t *testing.T) {
	const pebble = "https://127.0.0.1:14000/dir"

	cfg := loadWith(t, map[string]string{
		"CC01_ACME_EMAIL": "admin@cc01.uz",
		"CC01_ACME_DIR":   t.TempDir(),
		"CC01_ACME_CA":    pebble,
	})

	if cfg.ACMECA != pebble {
		t.Errorf("%q, %q kutilgan edi", cfg.ACMECA, pebble)
	}
}

// loadWith berilgan muhit bilan konfiguratsiyani yuklaydi.
func loadWith(t *testing.T, env map[string]string) Config {
	t.Helper()

	cfg, err := loadRaw(t, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// loadRaw muhitni t.Setenv orqali qo'yadi: test tugagach qiymatlar
// tiklanadi va keyingi testlar (-count>1 ham) toza muhitda ishlaydi.
func loadRaw(t *testing.T, env map[string]string) (Config, error) {
	t.Helper()

	base := map[string]string{
		"CC01_DOMAIN":     "cc01.uz",
		"CC01_TLS_CERT":   "/tmp/cert.pem",
		"CC01_TLS_KEY":    "/tmp/key.pem",
		"CC01_AUTH_MODE":  "disabled",
		"CC01_ACME_EMAIL": "",
		"CC01_ACME_DIR":   "",
		"CC01_ACME_CA":    "",

		"CC01_ACCESS_TLS_CA":          "",
		"CC01_ACCESS_TLS_CERT":        "",
		"CC01_ACCESS_TLS_KEY":         "",
		"CC01_ACCESS_TLS_SERVER_NAME": "",

		"CC01_USAGE_INTERVAL": "",
	}
	for key, value := range env {
		base[key] = value
	}

	for key, value := range base {
		t.Setenv(key, value)
	}

	var cfg Config
	err := cfg.Load()
	return cfg, err
}

// ── Ochiq tunnel yangilanishi ──────────────────────────────────

// setRenewEnv avtorizatsiya yoqilgan bazaviy muhitni qo'yadi.
func setRenewEnv(t *testing.T) {
	t.Helper()
	setBaseEnv(t)
	t.Setenv("CC01_AUTH_MODE", "")
	t.Setenv("CC01_ACCESS_ADDR", "127.0.0.1:5081")
	t.Setenv("CC01_ACME_EMAIL", "")
	t.Setenv("CC01_ACCESS_RENEW", "")
	t.Setenv("CC01_ACCESS_RENEW_DENY", "")
	t.Setenv("CC01_ACCESS_TIMEOUT", "")
	t.Setenv("CC01_USAGE_INTERVAL", "")
}

func TestLoad_AccessRenew(t *testing.T) {
	cases := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"", DefaultAccessRenew, false},
		{"0", 0, false}, // kill switch
		{"5", 5 * time.Second, false},
		{"1s", time.Second, false},
		{"50s", 50 * time.Second, false},
		{"55", 0, true},    // 50 s chegarasidan katta: 60 s kafolati buziladi
		{"2m", 0, true},    // 60 s dan katta
		{"500ms", 0, true}, // AP'ni ortiqcha yuklaydi
		{"-5s", 0, true},
		{"tez", 0, true},
	}

	for _, tc := range cases {
		t.Run("raw="+tc.raw, func(t *testing.T) {
			setRenewEnv(t)
			t.Setenv("CC01_ACCESS_RENEW", tc.raw)

			var conf Config
			err := conf.Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("xato kutilgan edi, AccessRenew=%s olindi", conf.AccessRenew)
				}
				if !strings.Contains(err.Error(), "CC01_ACCESS_RENEW") {
					t.Errorf("xato o'zgaruvchini zikr qilishi kerak: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("kutilmagan xato: %v", err)
			}
			if conf.AccessRenew != tc.want {
				t.Errorf("%s kutilgan, %s olindi", tc.want, conf.AccessRenew)
			}
		})
	}
}

// Avtorizatsiyasiz rejimda yangilaydigan AP yo'q — yangilash o'chadi.
func TestLoad_AccessRenewForcedOffWhenAuthDisabled(t *testing.T) {
	setRenewEnv(t)
	t.Setenv("CC01_AUTH_MODE", "disabled")
	t.Setenv("CC01_ACCESS_ADDR", "")
	t.Setenv("CC01_ACCESS_RENEW", "10s")

	var conf Config
	if err := conf.Load(); err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}
	if conf.AccessRenew != 0 {
		t.Errorf("AccessRenew: 0 kutilgan, %s olindi", conf.AccessRenew)
	}
}

func TestLoad_AccessRenewDeny(t *testing.T) {
	cases := []struct {
		raw     string
		want    RenewDenyMode
		wantErr bool
	}{
		{"", RenewDenyClose, false},
		{"close", RenewDenyClose, false},
		{"log", RenewDenyLog, false},
		{"Log", "", true},
		{"ignore", "", true},
	}

	for _, tc := range cases {
		t.Run("raw="+tc.raw, func(t *testing.T) {
			setRenewEnv(t)
			t.Setenv("CC01_ACCESS_RENEW_DENY", tc.raw)

			var conf Config
			err := conf.Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("xato kutilgan edi, %q olindi", conf.AccessRenewDeny)
				}
				if !strings.Contains(err.Error(), tc.raw) {
					t.Errorf("xato qiymatni ko'rsatishi kerak: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("kutilmagan xato: %v", err)
			}
			if conf.AccessRenewDeny != tc.want {
				t.Errorf("%q kutilgan, %q olindi", tc.want, conf.AccessRenewDeny)
			}
		})
	}
}

// 60 s kafolati konfiguratsiyada yashaydi: ruxsat etilgan eng katta
// oraliq ham taymaut va qayta ulanish bilan birga 60 s dan kichik.
func TestRenewBoundsKeepSLO(t *testing.T) {
	if b := AccessReconnectMax + DefaultAccessRenew + DefaultAccessTimeout; b >= AccessSLO {
		t.Errorf("standart: %s >= %s", b, AccessSLO)
	}
	if b := AccessReconnectMax + MaxAccessRenew + DefaultAccessTimeout; b >= AccessSLO {
		t.Errorf("chegara: %s >= %s", b, AccessSLO)
	}
}

// CC01_ACCESS_TIMEOUT ham 60 s kafolatiga kiradi: R + T (+ qayta ulanish)
// chegaradan oshsa server ishga tushmaydi. Ilgari faqat CC01_ACCESS_RENEW
// tekshirilardi va RENEW=50s + TIMEOUT=15s (65 s) jimgina qabul qilinardi.
func TestLoad_AccessRenewPlusTimeoutKeepsSLO(t *testing.T) {
	cases := []struct {
		renew, timeout string
		wantErr        bool
	}{
		{"", "", false},       // 6 + 30 + 3 = 39 s
		{"50s", "3s", false},  // 6 + 50 + 3 = 59 s
		{"50s", "15s", true},  // 71 s
		{"50s", "4s", true},   // 60 s — qat'iy kichik bo'lishi shart
		{"30s", "23s", false}, // 59 s
		{"30s", "24s", true},  // 60 s
		{"0", "45s", false},   // yangilash o'chiq — kafolat yo'q, tekshiruv ham
		{"10s", "43s", false}, // 59 s
	}

	for _, tc := range cases {
		t.Run("renew="+tc.renew+",timeout="+tc.timeout, func(t *testing.T) {
			setRenewEnv(t)
			t.Setenv("CC01_ACCESS_RENEW", tc.renew)
			t.Setenv("CC01_ACCESS_TIMEOUT", tc.timeout)

			var conf Config
			err := conf.Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("xato kutilgan edi: RENEW=%s TIMEOUT=%s qabul qilindi",
						conf.AccessRenew, conf.AccessTimeout)
				}
				for _, name := range []string{"CC01_ACCESS_RENEW", "CC01_ACCESS_TIMEOUT"} {
					if !strings.Contains(err.Error(), name) {
						t.Errorf("xato %s ni zikr qilishi kerak: %v", name, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("kutilmagan xato: %v", err)
			}
		})
	}
}

// Avtorizatsiyasiz rejimda yangilash yo'q — taymaut kafolatga kirmaydi.
func TestLoad_AccessTimeoutNotBoundWhenAuthDisabled(t *testing.T) {
	setRenewEnv(t)
	t.Setenv("CC01_AUTH_MODE", "disabled")
	t.Setenv("CC01_ACCESS_ADDR", "")
	t.Setenv("CC01_ACCESS_TIMEOUT", "70s")

	var conf Config
	if err := conf.Load(); err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}
}

func TestLoad_AccessTimeoutMustBePositive(t *testing.T) {
	for _, raw := range []string{"0", "-1s"} {
		t.Run(raw, func(t *testing.T) {
			setRenewEnv(t)
			t.Setenv("CC01_ACCESS_TIMEOUT", raw)

			var conf Config
			err := conf.Load()
			if err == nil || !strings.Contains(err.Error(), "CC01_ACCESS_TIMEOUT") {
				t.Fatalf("CC01_ACCESS_TIMEOUT xatosi kutilgan, olindi: %v", err)
			}
		})
	}
}

// ── Foydalanish hisoboti ──────────────────────────────────

func TestLoad_UsageInterval(t *testing.T) {
	cases := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"", DefaultUsageInterval, false},
		{"0", 0, false}, // o'chirish
		{"5", 5 * time.Second, false},
		{"5s", 5 * time.Second, false},
		{"90s", 90 * time.Second, false},
		{"5m", 5 * time.Minute, false},
		{"300", 300 * time.Second, false},
		{"4s", 0, true},     // AP'ni ortiqcha yuklaydi
		{"301s", 0, true},   // juda uzun
		{"10m", 0, true},    // juda uzun
		{"7500ms", 0, true}, // butun sekund emas
		{"-60s", 0, true},
		{"daqiqa", 0, true},
	}

	for _, tc := range cases {
		t.Run("raw="+tc.raw, func(t *testing.T) {
			setRenewEnv(t)
			t.Setenv("CC01_USAGE_INTERVAL", tc.raw)

			var conf Config
			err := conf.Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("xato kutilgan edi, UsageInterval=%s olindi", conf.UsageInterval)
				}
				if !strings.Contains(err.Error(), "CC01_USAGE_INTERVAL") {
					t.Errorf("xato o'zgaruvchini zikr qilishi kerak: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("kutilmagan xato: %v", err)
			}
			if conf.UsageInterval != tc.want {
				t.Errorf("%s kutilgan, %s olindi", tc.want, conf.UsageInterval)
			}
		})
	}
}

// Avtorizatsiyasiz rejimda hisobot qabul qiladigan AP yo'q — o'chadi.
// Yaroqsiz qiymat esa baribir rad etiladi (renew bilan bir xil).
func TestLoad_UsageIntervalForcedOffWhenAuthDisabled(t *testing.T) {
	cfg := loadWith(t, map[string]string{"CC01_USAGE_INTERVAL": "10s"})
	if cfg.UsageInterval != 0 {
		t.Errorf("UsageInterval: 0 kutilgan, %s olindi", cfg.UsageInterval)
	}
	if _, err := loadRaw(t, map[string]string{"CC01_USAGE_INTERVAL": "1s"}); err == nil {
		t.Error("yaroqsiz qiymat disabled rejimda ham rad etilishi kerak")
	}
}
