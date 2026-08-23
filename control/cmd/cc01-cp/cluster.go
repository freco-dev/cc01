package main

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/freco-dev/cc01/control/cluster"
	"github.com/freco-dev/cc01/control/ipam"
)

// openStore IPAM uchun holat omborini tanlaydi.
//
// Klaster sozlanmagan bo'lsa — xotiradagi ombor. U bitta jarayon
// uchun to'liq to'g'ri ishlaydi, lekin jarayon o'lganda hamma ijara
// yo'qoladi va nodelar yangi manzil oladi.
func openStore(cfg runConfig, logger *slog.Logger) (ipam.Store, func() error, error) {
	if cfg.raftBind == "" {
		logger.Warn("klaster sozlanmagan — holat XOTIRADA saqlanadi va " +
			"qayta ishga tushirilganda YO'QOLADI; ishlab chiqarish uchun -raft-bind bering")
		return ipam.NewMemoryStore(), func() error { return nil }, nil
	}

	peers, err := parsePeers(cfg.raftPeers)
	if err != nil {
		return nil, nil, err
	}

	node, err := cluster.Start(cluster.Config{
		ID:        cfg.raftID,
		Bind:      cfg.raftBind,
		Advertise: cfg.raftAdvertise,
		Dir:       cfg.raftDir,
		Bootstrap: cfg.raftBootstrap,
		Peers:     peers,
		Logger:    logger,
	})
	if err != nil {
		return nil, nil, err
	}

	return node, node.Close, nil
}

// parsePeers "id=host:port,id=host:port" ro'yxatini o'qiydi.
func parsePeers(list string) ([]cluster.Peer, error) {
	if strings.TrimSpace(list) == "" {
		return nil, nil
	}

	var peers []cluster.Peer
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		id, address, ok := strings.Cut(item, "=")
		if !ok || id == "" || address == "" {
			return nil, fmt.Errorf("-raft-peers: %q yaroqsiz, kerakli shakl: id=host:port", item)
		}
		peers = append(peers, cluster.Peer{ID: strings.TrimSpace(id), Address: strings.TrimSpace(address)})
	}

	return peers, nil
}
