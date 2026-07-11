package config

import (
	"errors"
	"os"
)

type Config struct {
	DomainName          string
	MaxConsPerTunnel    int
	EventServerPort     uint16
	PublicServerPort    uint16
	PublicServerTLSPort uint16
	TLSCertFile         string
	TLSKeyFile          string
}

func (c *Config) Load() error {
	c.MaxConsPerTunnel = 24
	c.PublicServerPort = 80
	c.EventServerPort = 4321
	c.PublicServerTLSPort = 443
	c.DomainName = os.Getenv("CC01_DOMAIN")
	c.TLSKeyFile = os.Getenv("CC01_TLS_KEY")
	c.TLSCertFile = os.Getenv("CC01_TLS_CERT")

	if c.DomainName == "" {
		return errors.New("cc01 domain env is not set")
	}
	if c.TLSKeyFile == "" || c.TLSCertFile == "" {
		return errors.New("TLS key/cert file is missing")
	}
	return nil
}
