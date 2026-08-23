// cc01-cp — Control Plane demoni.
//
// Hozircha bitta jarayon: node registri, IPAM va NetworkMap stream'i.
// Raft klasteri `Store` interfeysi ortida keyin qo'shiladi
// (ARCHITECTURE.md §3.1.6, ADR-006).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/freco-dev/cc01/control/ipam"
	"github.com/freco-dev/cc01/control/registry"
	"github.com/freco-dev/cc01/control/server"
	"github.com/freco-dev/cc01/control/stunserver"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc"
)

func main() {
	var (
		listen    = flag.String("listen", ":8443", "gRPC manzili")
		stunAddr  = flag.String("stun", ":3478", "STUN serveri manzili; bo'sh bo'lsa o'chiriladi")
		relayPort = flag.Uint("relay", 0, "relay serveri porti; 0 bo'lsa o'chiriladi")
		relayHost = flag.String("relay-endpoint", "", "relayning e'lon qilinadigan manzili host:port")
		tenantNet = flag.String("tenant-net", "", "nodelarga manzil beriladigan prefiks, masalan 2a0e:1234:1::/64")
		authToken = flag.String("auth-token", os.Getenv("CC01_CP_TOKEN"), "nodelar uchun oldindan kelishilgan sir")
		authMode  = flag.String("auth-mode", os.Getenv("CC01_CP_AUTH_MODE"), "required (standart) yoki disabled")
		tlsCert   = flag.String("tls-cert", "", "TLS sertifikati (PEM); bo'sh bo'lsa vaqtinchalik yaratiladi")
		tlsKey    = flag.String("tls-key", "", "TLS kaliti (PEM)")
		tlsHosts  = flag.String("tls-hosts", "", "sertifikatga yoziladigan nomlar/IP'lar, vergul bilan")
		noTLS     = flag.Bool("insecure", false, "kanalni shifrlamaslik (FAQAT lokal sinov)")

		raftID        = flag.String("raft-id", os.Getenv("CC01_RAFT_ID"), "klasterdagi noyob identifikator")
		raftBind      = flag.String("raft-bind", os.Getenv("CC01_RAFT_BIND"), "Raft transporti manzili; bo'sh bo'lsa klaster o'chiriladi")
		raftAdvertise = flag.String("raft-advertise", os.Getenv("CC01_RAFT_ADVERTISE"), "boshqa nodelarga ko'rinadigan Raft manzili")
		raftDir       = flag.String("raft-dir", os.Getenv("CC01_RAFT_DIR"), "jurnal va snapshot papkasi")
		raftPeers     = flag.String("raft-peers", os.Getenv("CC01_RAFT_PEERS"), "boshlang'ich a'zolar: id=host:port,id=host:port")
		raftBootstrap = flag.Bool("raft-bootstrap", false, "klasterni SHU node bilan boshlash (faqat bittasida!)")
		verbose       = flag.Bool("v", false, "batafsil log")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := run(runConfig{
		listen: *listen, stun: *stunAddr, tenantNet: *tenantNet,
		authToken: *authToken, authMode: *authMode,
		relayPort: uint16(*relayPort), relayHost: *relayHost,
		tlsCert: *tlsCert, tlsKey: *tlsKey,
		tlsHosts: splitHosts(*tlsHosts), insecure: *noTLS,
		raftID: *raftID, raftBind: *raftBind, raftAdvertise: *raftAdvertise,
		raftDir: *raftDir, raftPeers: *raftPeers, raftBootstrap: *raftBootstrap,
	}, logger); err != nil {
		fmt.Fprintf(os.Stderr, "cc01-cp: %v\n", err)
		os.Exit(1)
	}
}

type runConfig struct {
	listen    string
	stun      string
	tenantNet string
	authToken string
	authMode  string
	relayPort uint16
	relayHost string

	tlsCert  string
	tlsKey   string
	tlsHosts []string
	insecure bool

	raftID        string
	raftBind      string
	raftAdvertise string
	raftDir       string
	raftPeers     string
	raftBootstrap bool
}

// splitHosts vergul bilan ajratilgan ro'yxatni bo'ladi.
func splitHosts(list string) []string {
	if strings.TrimSpace(list) == "" {
		return nil
	}

	parts := strings.Split(list, ",")
	hosts := make([]string, 0, len(parts))
	for _, part := range parts {
		if host := strings.TrimSpace(part); host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func run(cfg runConfig, logger *slog.Logger) error {
	listen, stunAddr, tenantNet := cfg.listen, cfg.stun, cfg.tenantNet
	authToken, authMode := cfg.authToken, cfg.authMode
	prefix, err := netip.ParsePrefix(tenantNet)
	if err != nil {
		return fmt.Errorf("-tenant-net: %w", err)
	}

	// Deny-by-default (ARCHITECTURE.md §1.5): autentifikatsiyani
	// o'chirish OSHKORA yozilishi kerak.
	switch authMode {
	case "", "required":
		if authToken == "" {
			return errors.New(
				"-auth-token berilmagan (yoki CC01_CP_TOKEN).\n" +
					"  Nodelar tekshiruvsiz ro'yxatdan o'tmasligi uchun server ishga tushmadi.\n" +
					"  Yechim: -auth-token <sir>, yoki lokal sinov uchun oshkora:\n" +
					"      CC01_CP_AUTH_MODE=disabled")
		}
	case "disabled":
		logger.Warn("AUTENTIFIKATSIYA O'CHIRILGAN — har qanday node ro'yxatdan o'ta oladi; " +
			"bu rejim faqat lokal ishlab chiqish uchun")
		authToken = ""
	default:
		return fmt.Errorf("-auth-mode noma'lum: %q (required yoki disabled)", authMode)
	}

	nodes := registry.New(registry.Options{})

	store, identities, closeStore, err := openStore(cfg, logger)
	if err != nil {
		return err
	}
	defer closeStore()

	allocator, err := ipam.New(ipam.Options{Store: store})
	if err != nil {
		return err
	}

	service, err := server.New(server.Config{
		Registry:     nodes,
		Allocator:    allocator,
		TenantPrefix: prefix,
		AuthToken:    authToken,
		Identities:   identities,
		Logger:       logger,
	})
	if err != nil {
		return err
	}

	// STUN serveri gRPC bilan bir jarayonda: NAT ortidagi node
	// o'zining public manzilini boshqa yo'l bilan bila olmaydi
	// (ARCHITECTURE.md §3.1.4).
	if stunAddr != "" {
		stunSrv, err := stunserver.Listen(stunAddr, logger)
		if err != nil {
			return err
		}
		defer stunSrv.Close()

		go stunSrv.Serve()
		logger.Info("STUN serveri tayyor", "listen", stunSrv.Addr().String())
	}

	// Relay CP bilan bir jarayonda ishlashi mumkin — bu bitta
	// mashinali o'rnatish uchun. Arxitekturada relay Edge Plane
	// komponenti (§3.3.2) va alohida PoP'da turadi.
	if cfg.relayPort != 0 {
		stopRelay, err := startRelay(nodes, cfg, logger)
		if err != nil {
			return err
		}
		defer stopRelay()
	}

	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("tinglash (%s): %w", listen, err)
	}

	opts, err := serverOptions(cfg, logger)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer(opts...)
	cc01v1.RegisterControlServiceServer(grpcServer, service)

	// Muddati o'tgan nodelarni davriy tozalaymiz.
	stopSweeper := make(chan struct{})
	go sweepExpired(nodes, allocator, logger, stopSweeper)

	logger.Info("cc01-cp tayyor",
		"listen", listener.Addr().String(),
		"tenant_net", prefix.String(),
		"auth", authMode == "" || authMode == "required",
		"tls", !cfg.insecure,
		"klaster", cfg.raftBind != "")

	errc := make(chan error, 1)
	go func() { errc <- grpcServer.Serve(listener) }()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errc:
		return err
	case <-signals:
		logger.Info("to'xtatilmoqda")
		close(stopSweeper)
		grpcServer.GracefulStop()
		return nil
	}
}

// sweepExpired heartbeat yubormay qo'ygan nodelarni va muddati o'tgan
// ijaralarni tozalaydi.
func sweepExpired(
	nodes *registry.Registry,
	allocator *ipam.Allocator,
	logger *slog.Logger,
	stop <-chan struct{},
) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if removed := nodes.Expire(); removed > 0 {
				logger.Info("muddati o'tgan nodelar chiqarildi", "count", removed)
			}
			if reclaimed, err := allocator.Reclaim(context.Background()); err != nil {
				logger.Error("ijaralarni tozalash", "err", err)
			} else if reclaimed > 0 {
				logger.Info("ijaralar bo'shatildi", "count", reclaimed)
			}
		}
	}
}
