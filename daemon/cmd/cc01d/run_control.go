package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/control"
	"github.com/freco-dev/cc01/daemon/engine"
	"github.com/freco-dev/cc01/daemon/tun"
)

type controlConfig struct {
	privateKey  string
	controlAddr string
	tenant      string
	hostname    string
	authToken   string
	listenPort  uint16
	ifaceName   string
	advertised  []netip.AddrPort

	// stunServer — bo'sh bo'lmasa, ro'yxatdan o'tishdan OLDIN public
	// manzil aniqlanadi va u ham e'lon qilinadi.
	stunServer netip.AddrPort
}

// runWithControlPlane — CP rejimi: peerlar qo'lda emas, CP dan keladi.
//
// Ketma-ketlik muhim:
//  1. UDP soketi ochiladi — endpointni e'lon qilish uchun port kerak
//  2. CP da ro'yxatdan o'tiladi — manzil aynan shu yerda beriladi
//  3. TUN yaratiladi — manzil endi ma'lum
//  4. Engine ishga tushadi
//  5. CP stream'i peerlarni to'ldiradi
func runWithControlPlane(cfg controlConfig, logger *slog.Logger) error {
	identity, err := loadIdentity(cfg.privateKey)
	if err != nil {
		return err
	}

	bind, err := conn.Open(cfg.listenPort)
	if err != nil {
		return err
	}

	endpoints := cfg.advertised
	if len(endpoints) == 0 {
		endpoints = localEndpoints(bind.Port())
	}
	if len(endpoints) == 0 {
		_ = bind.Close()
		return fmt.Errorf("underlay manzil topilmadi; -advertise bilan ko'rsating")
	}

	// Endpointlarni e'lon qilishdan oldin STUN so'raymiz. Buning uchun
	// engine kerak (u soketni boshqaradi), engine uchun esa TUN kerak,
	// TUN uchun esa manzil — ya'ni ro'yxatdan o'tish. Halqani uzish
	// uchun STUN'ni engine'siz, to'g'ridan-to'g'ri soket orqali
	// bajaramiz: NAT bog'lanishi soketga bog'langan, ya'ni natija bir xil.
	if cfg.stunServer.IsValid() {
		if mapped, err := discoverPublic(bind, cfg.stunServer); err != nil {
			logger.Warn("public manzil aniqlanmadi, lokal manzillar ishlatiladi",
				"stun", cfg.stunServer, "err", err)
		} else {
			logger.Info("public manzil aniqlandi", "endpoint", mapped)
			endpoints = append([]netip.AddrPort{mapped}, endpoints...)
		}
	}

	// Relay ro'yxati NetworkMap bilan keladi, engine esa hali
	// yaratilmagan — shuning uchun uni keyinroq ulaymiz.
	relayLink := newRelayLink(identity, bind, logger)

	client, err := control.Dial(control.Config{
		Address:   cfg.controlAddr,
		Identity:  identity,
		Tenant:    cfg.tenant,
		Hostname:  cfg.hostname,
		Endpoints: endpoints,
		AuthToken: cfg.authToken,
		OnRelays:  relayLink.update,
		Logger:    logger,
	})
	if err != nil {
		_ = bind.Close()
		return err
	}
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registration, err := client.Register(ctx)
	if err != nil {
		_ = bind.Close()
		return err
	}

	device, err := tun.Create(tun.Config{
		Name:      cfg.ifaceName,
		Addresses: []netip.Prefix{registration.Address},
		Routes:    []netip.Prefix{registration.TenantCIDR},
	})
	if err != nil {
		_ = bind.Close()
		return err
	}

	datapath, err := engine.New(engine.Config{
		Identity: identity,
		Device:   device,
		Bind:     bind,
		Logger:   logger,
	})
	if err != nil {
		_ = device.Close()
		_ = bind.Close()
		return err
	}

	// Router engine bilan birga tug'iladi, ro'yxatdan o'tish esa
	// undan oldin bo'ladi — shuning uchun uni endi ulaymiz.
	client.SetRouter(datapath.Router())
	relayLink.attach(datapath)
	datapath.Start()

	logger.Info("cc01d tayyor (CP rejimi)",
		"pubkey", identity.PublicKey().String(),
		"node", registration.NodeID[:12],
		"iface", device.Name(),
		"addr", registration.Address.String(),
		"cp", cfg.controlAddr)

	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		if err := client.Run(ctx, registration.HeartbeatInterval); err != nil {
			logger.Error("CP klienti to'xtadi", "err", err)
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals

	logger.Info("to'xtatilmoqda")
	cancel()
	<-streamDone
	relayLink.close()

	return datapath.Close()
}
