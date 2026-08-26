package main

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/freco-dev/cc01/control/registry"
	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/relay"
)

// startRelay relay serverini ko'taradi va uni CP ro'yxatiga qo'shadi.
//
// Relayning public kaliti NetworkMap orqali nodelarga yetkaziladi —
// Noise IK patterni klientdan uni OLDINDAN bilishni talab qiladi.
func startRelay(
	nodes *registry.Registry,
	cfg runConfig,
	logger *slog.Logger,
) (func(), error) {
	identity, err := noise.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("relay kaliti: %w", err)
	}

	bind, err := conn.Open(cfg.relayPort)
	if err != nil {
		return nil, fmt.Errorf("relay soketi: %w", err)
	}

	server, err := relay.NewServer(relay.Options{
		Identity: identity,
		Bind:     bind,
		Logger:   logger,
	})
	if err != nil {
		_ = bind.Close()
		return nil, err
	}

	// E'lon qilinadigan manzil: nodelar unga tashqaridan ulanadi,
	// shuning uchun u tinglash manzilidan farq qilishi mumkin.
	advertised := cfg.relayHost
	if advertised == "" {
		advertised = server.Addr().String()
	}

	endpoint, err := netip.ParseAddrPort(advertised)
	if err != nil {
		_ = server.Close()
		return nil, fmt.Errorf("-relay-endpoint: %w", err)
	}

	var key registry.PublicKey
	copy(key[:], identity.PublicKey().Bytes())

	nodes.SetRelays([]registry.Relay{{
		ID:        "relay-1",
		PublicKey: key,
		Endpoint:  endpoint,
		Region:    "local",
		Priority:  1,
	}})

	go server.Serve()

	logger.Info("relay tayyor",
		"listen", server.Addr().String(),
		"advertised", endpoint.String(),
		"pubkey", identity.PublicKey().String())

	return func() { _ = server.Close() }, nil
}
