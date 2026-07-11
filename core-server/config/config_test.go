package config

import (
	"fmt"
	"testing"
)

func TestConfig_Load(t *testing.T) {
	t.Setenv("CC01_DOMAIN", "cc01.site")
	t.Setenv("CC01_TLS_KEY", "key.pem")
	t.Setenv("CC01_TLS_CERT", "cert.pem")

	config := &Config{}
	err := config.Load()
	if err != nil {
		t.Logf("Error while loading the config: %v", err.Error())
		t.Fail()
	}
}

func TestConfig_loadEmptyEnv(t *testing.T) {
	envs := []struct {
		key     string
		value   string
		ErrText string
	}{
		{
			"CC01_DOMAIN",
			"cc01.site",
			"cc01 domain env is not set",
		},
		{
			"CC01_TLS_KEY",
			"example.key",
			"TLS key/cert file is missing",
		},
		{
			"CC01_TLS_CERT",
			"example.cert",
			"TLS key/cert file is missing",
		},
	}

	for i, missing := range envs {
		t.Run(fmt.Sprintf("Missing %s", missing.key), func(t *testing.T) {
			for j, env := range envs {
				if i == j {
					continue
				}
				t.Setenv(env.key, env.value)
			}
			config := &Config{}
			err := config.Load()

			if err == nil {
				t.Logf("expected %v, but got %v", missing.ErrText, err)
			}
			if err.Error() != missing.ErrText {
				t.Logf("expected %s, but got %s", missing.ErrText, err.Error())
			}
		})
	}
}
