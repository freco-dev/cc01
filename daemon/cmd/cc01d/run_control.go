package main

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/freco-dev/cc01/daemon/ipc"
	"github.com/freco-dev/cc01/daemon/session"
)

type controlConfig struct {
	privateKey  string
	controlAddr string
	tenant      string
	hostname    string
	authToken   string
	listenPort  uint16
	ifaceName   string
	socketPath  string
	advertised  []netip.AddrPort

	// stunServer — bo'sh bo'lmasa, ro'yxatdan o'tishdan OLDIN public
	// manzil aniqlanadi va u ham e'lon qilinadi.
	stunServer netip.AddrPort

	// startDown — demon mesh'ni ko'tarmasdan ishga tushadi va
	// `cc01 up` ni kutadi.
	startDown bool
}

// upTimeout — `cc01 up` ro'yxatdan o'tishni qancha kutadi.
//
// Cheklov kerak: CP javob bermasa, chaqiruv abadiy osilib qolmasligi
// va IPC qulfini ushlab turmasligi kerak.
const upTimeout = 30 * time.Second

// runWithControlPlane — CP rejimi: peerlar qo'lda emas, CP dan keladi.
//
// Demon va mesh endi alohida umr ko'radi. Demon IPC soketini ochadi va
// signalgacha yashaydi; mesh esa `cc01 up`/`down` bilan bir necha marta
// ko'tarilib tushishi mumkin.
func runWithControlPlane(cfg controlConfig, logger *slog.Logger) error {
	identity, err := loadIdentity(cfg.privateKey)
	if err != nil {
		return err
	}

	mesh := session.New(session.Config{
		Identity:    identity,
		ControlAddr: cfg.controlAddr,
		Tenant:      cfg.tenant,
		Hostname:    cfg.hostname,
		AuthToken:   cfg.authToken,
		ListenPort:  cfg.listenPort,
		IfaceName:   cfg.ifaceName,
		Advertised:  cfg.advertised,
		StunServer:  cfg.stunServer,
		Logger:      logger,
	})

	// IPC mesh'dan OLDIN ochiladi: mesh ko'tarilmasa ham `cc01 status`
	// va `cc01 doctor` ishlashi kerak — aks holda nosozlikni aynan
	// kerak bo'lgan paytda ko'rib bo'lmaydi.
	ipcServer, err := ipc.Listen(cfg.socketPath, ipc.NewService(mesh, version), logger)
	if err != nil {
		logger.Warn("IPC ochilmadi, `cc01 status` ishlamaydi", "err", err)
	} else {
		defer ipcServer.Close()
		go func() {
			if err := ipcServer.Serve(); err != nil {
				logger.Error("IPC to'xtadi", "err", err)
			}
		}()
	}

	if cfg.startDown {
		logger.Info("cc01d tayyor (mesh tushirilgan) — ko'tarish: cc01 up",
			"socket", cfg.socketPath)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), upTimeout)
		err := mesh.Up(ctx)
		cancel()

		if err != nil {
			return err
		}
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals

	logger.Info("to'xtatilmoqda")
	return mesh.Down()
}
