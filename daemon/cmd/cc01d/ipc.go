package main

import (
	"log/slog"
	"net/netip"

	"github.com/freco-dev/cc01/daemon/control"
	"github.com/freco-dev/cc01/daemon/engine"
	"github.com/freco-dev/cc01/daemon/ipc"
)

// startIPC CLI uchun mahalliy boshqaruv soketini ochadi.
func startIPC(
	cfg controlConfig,
	datapath *engine.Engine,
	registration *control.Registration,
	endpoints []netip.AddrPort,
	relays *relayLink,
	routes ipc.RouteStatus,
	logger *slog.Logger,
) (*ipc.Server, error) {
	advertised := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		advertised = append(advertised, endpoint.String())
	}

	service := ipc.NewService(datapath, ipc.Info{
		NodeID:       registration.NodeID,
		Hostname:     cfg.hostname,
		Tenant:       cfg.tenant,
		Address:      registration.Address.String(),
		ControlPlane: cfg.controlAddr,
		Endpoints:    advertised,
		Version:      version,
		RelayID:      relays.activeID,
		Routes:       routes,
	})

	server, err := ipc.Listen(cfg.socketPath, service, logger)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := server.Serve(); err != nil {
			logger.Error("IPC to'xtadi", "err", err)
		}
	}()

	return server, nil
}
