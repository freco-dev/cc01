package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/control"
	"github.com/freco-dev/cc01/daemon/engine"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/relay"
)

// relayLink CP e'lon qilgan relayga ulanishni boshqaradi.
//
// Vaqt bo'yicha nozik joyi: relay ro'yxati NetworkMap bilan keladi,
// ya'ni engine allaqachon ishlab turgan bo'ladi. Relay klienti esa
// datapath soketini ishlatadi — o'z soketini ochsa, NAT ortida
// ALOHIDA bog'lanish yaratardi va relay bizni boshqa manzilda ko'rardi.
type relayLink struct {
	identity *noise.Identity
	bind     *conn.Bind
	log      *slog.Logger

	mu      sync.Mutex
	engine  *engine.Engine
	current *relay.Client
	active  string // ulangan relayning ID'si
}

func newRelayLink(identity *noise.Identity, bind *conn.Bind, logger *slog.Logger) *relayLink {
	return &relayLink{identity: identity, bind: bind, log: logger}
}

// attach engine yaratilgach chaqiriladi.
func (l *relayLink) attach(datapath *engine.Engine) {
	l.mu.Lock()
	l.engine = datapath
	client := l.current
	l.mu.Unlock()

	// Ro'yxat engine'dan oldin kelgan bo'lishi mumkin.
	if client != nil {
		datapath.SetRelay(client)
	}
}

// update CP dan kelgan relay ro'yxatini qo'llaydi.
//
// Ro'yxat allaqachon ustuvorlik bo'yicha tartiblangan, shuning uchun
// birinchisini tanlaymiz. Bir nechta relay orasidan RTT bo'yicha
// tanlash (§6.4) keyingi qadam.
func (l *relayLink) update(relays []control.RelayInfo) {
	if len(relays) == 0 {
		return
	}
	chosen := relays[0]

	l.mu.Lock()
	if l.active == chosen.ID && l.current != nil {
		l.mu.Unlock()
		return
	}
	previous := l.current
	l.mu.Unlock()

	client, err := relay.NewClient(relay.ClientOptions{
		Identity: l.identity,
		RelayKey: chosen.PublicKey,
		Endpoint: chosen.Endpoint,
		Send:     l.bind.Send,
	})
	if err != nil {
		l.log.Warn("relay klienti yaratilmadi", "relay", chosen.ID, "err", err)
		return
	}

	// Engine relay javoblarini demultiplekslashi uchun uni DARHOL
	// ulaymiz — handshake javobi aks holda yo'qolardi.
	l.mu.Lock()
	l.current = client
	l.active = chosen.ID
	datapath := l.engine
	l.mu.Unlock()

	if datapath != nil {
		datapath.SetRelay(client)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		l.log.Warn("relayga ulanib bo'lmadi",
			"relay", chosen.ID, "endpoint", chosen.Endpoint, "err", err)

		l.mu.Lock()
		l.current = previous
		l.active = ""
		l.mu.Unlock()

		if datapath != nil {
			datapath.SetRelay(previous)
		}
		return
	}

	l.log.Info("relayga ulandi",
		"relay", chosen.ID, "region", chosen.Region, "endpoint", chosen.Endpoint)

	go l.keepalive(client)
}

// keepalive relaydagi sessiyani va NAT bog'lanishini tirik ushlaydi.
func (l *relayLink) keepalive(client *relay.Client) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		current := l.current
		l.mu.Unlock()

		if current != client {
			return // boshqa relayga o'tildi
		}
		if err := client.Keepalive(); err != nil {
			return
		}
	}
}

// activeID — ulangan relayning ID'si; ulanmagan bo'lsa bo'sh.
func (l *relayLink) activeID() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.current == nil {
		return ""
	}
	return l.active
}

func (l *relayLink) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.current = nil
}
