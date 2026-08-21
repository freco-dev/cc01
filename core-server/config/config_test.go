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
