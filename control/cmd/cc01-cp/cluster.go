package main

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/freco-dev/cc01/control/cluster"
	"github.com/freco-dev/cc01/control/ipam"
	"github.com/freco-dev/cc01/control/registry"
)

// openStore IPAM uchun holat omborini tanlaydi.
//
// Klaster sozlanmagan bo'lsa — xotiradagi ombor. U bitta jarayon
// uchun to'liq to'g'ri ishlaydi, lekin jarayon o'lganda hamma ijara
// yo'qoladi va nodelar yangi manzil oladi.
// stores — CP ning holat omborlari.
type stores struct {
	leases     ipam.Store
	identities cluster.IdentityStore
	nodes      cluster.NodeStore
	close      func() error
}

func openStore(
	cfg runConfig,
	nodes *registry.Registry,
	logger *slog.Logger,
) (stores, error) {
	if cfg.raftBind == "" {
		logger.Warn("klaster sozlanmagan — holat XOTIRADA saqlanadi va " +
			"qayta ishga tushirilganda YO'QOLADI; ishlab chiqarish uchun -raft-bind bering")
		return stores{
			leases:     ipam.NewMemoryStore(),
			identities: cluster.NewMemoryIdentities(),
			nodes:      cluster.NewMemoryNodes(nodes),
			close:      func() error { return nil },
		}, nil
	}

	peers, err := parsePeers(cfg.raftPeers)
	if err != nil {
		return stores{}, err
	}

	node, err := cluster.Start(cluster.Config{
		ID:        cfg.raftID,
		Bind:      cfg.raftBind,
		Advertise: cfg.raftAdvertise,
		Dir:       cfg.raftDir,
		Bootstrap: cfg.raftBootstrap,
		Peers:     peers,
		Nodes:     nodes,
		Logger:    logger,
	})
	if err != nil {
		return stores{}, err
	}

	// Bitta Raft node hamma rolni bajaradi: ijaralar, node
	// bog'lanishlari va node ro'yxati bir xil jurnal orqali ketadi.
	return stores{
		leases:     node,
		identities: node,
		nodes:      node,
		close:      node.Close,
	}, nil
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
