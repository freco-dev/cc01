// cc01d — mesh datapath demoni.
//
// Hozircha minimal: statik peer konfiguratsiyasi bilan ikki node
// o'rtasida shifrlangan overlay quradi. Control Plane, IPAM va NAT
// traversal Faza 1 ning keyingi qismlarida qo'shiladi.
//
// Kalit yaratish:
//
//	cc01d -genkey
//
// Ishga tushirish:
//
//	cc01d -key <private> -addr 2a0e:1::1/128 -listen 51820 \
//	      -peer-key <public> -peer-endpoint 10.0.0.2:51820 \
//	      -peer-allowed 2a0e:1::2/128
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/engine"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/tun"
)

func main() {
	var (
		genKey       = flag.Bool("genkey", false, "yangi kalit jufti yaratadi va chiqaradi")
		privateKey   = flag.String("key", os.Getenv("CC01_PRIVATE_KEY"), "base64 private kalit")
		listenPort   = flag.Uint("listen", conn.DefaultPort, "overlay UDP porti")
		ifaceName    = flag.String("iface", tun.DefaultName, "TUN interfeys nomi")
		localAddr    = flag.String("addr", "", "overlay manzili, masalan 2a0e:1::1/128")
		peerKey      = flag.String("peer-key", "", "peerning base64 public kaliti")
		peerEndpoint = flag.String("peer-endpoint", "", "peerning underlay manzili host:port")
		peerAllowed  = flag.String("peer-allowed", "", "peerning allowed_ips prefiksi")
		verbose      = flag.Bool("v", false, "batafsil log")
	)
	flag.Parse()

	if *genKey {
		if err := printNewKeyPair(); err != nil {
			fail(err)
		}
		return
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := run(config{
		privateKey:   *privateKey,
		listenPort:   uint16(*listenPort),
		ifaceName:    *ifaceName,
		localAddr:    *localAddr,
		peerKey:      *peerKey,
		peerEndpoint: *peerEndpoint,
		peerAllowed:  *peerAllowed,
	}, logger); err != nil {
		fail(err)
	}
}

type config struct {
	privateKey   string
	listenPort   uint16
	ifaceName    string
	localAddr    string
	peerKey      string
	peerEndpoint string
	peerAllowed  string
}

func run(cfg config, logger *slog.Logger) error {
	identity, err := loadIdentity(cfg.privateKey)
	if err != nil {
		return err
	}

	address, err := netip.ParsePrefix(cfg.localAddr)
	if err != nil {
		return fmt.Errorf("-addr: %w", err)
	}

	peerPublic, err := noise.ParsePublicKey(cfg.peerKey)
	if err != nil {
		return fmt.Errorf("-peer-key: %w", err)
	}

	endpoint, err := netip.ParseAddrPort(cfg.peerEndpoint)
	if err != nil {
		return fmt.Errorf("-peer-endpoint: %w", err)
	}

	allowed, err := netip.ParsePrefix(cfg.peerAllowed)
	if err != nil {
		return fmt.Errorf("-peer-allowed: %w", err)
	}

	device, err := tun.Create(tun.Config{
		Name:      cfg.ifaceName,
		Addresses: []netip.Prefix{address},
		Routes:    []netip.Prefix{allowed},
	})
	if err != nil {
		return err
	}

	bind, err := conn.Open(cfg.listenPort)
	if err != nil {
		_ = device.Close()
		return err
	}

	datapath, err := engine.New(engine.Config{
		Identity: identity,
		Device:   device,
		Bind:     bind,
		Logger:   logger,
	})
	if err != nil {
		_ = bind.Close()
		_ = device.Close()
		return err
	}

	if _, err := datapath.AddPeer(peerPublic, []netip.Prefix{allowed}, endpoint); err != nil {
		_ = datapath.Close()
		return err
	}

	datapath.Start()

	logger.Info("cc01d tayyor",
		"pubkey", identity.PublicKey().String(),
		"iface", device.Name(),
		"addr", address.String(),
		"peer", peerPublic.String())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals

	logger.Info("to'xtatilmoqda")
	return datapath.Close()
}

func loadIdentity(encoded string) (*noise.Identity, error) {
	if encoded == "" {
		return nil, fmt.Errorf("-key berilmagan (yoki CC01_PRIVATE_KEY); " +
			"yangi kalit uchun: cc01d -genkey")
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("-key: base64 dekodlash: %w", err)
	}

	return noise.IdentityFromPrivate(raw)
}

func printNewKeyPair() error {
	identity, err := noise.GenerateIdentity()
	if err != nil {
		return err
	}

	// Private kalit stdout'ga, public — stderr'ga: shunda skript
	// private kalitni oson olishi mumkin, public esa ko'rinib turadi.
	fmt.Println(base64.StdEncoding.EncodeToString(identity.MarshalPrivateKey()))
	fmt.Fprintf(os.Stderr, "public: %s\n", identity.PublicKey())
	return nil
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "cc01d: %v\n", err)
	os.Exit(1)
}
