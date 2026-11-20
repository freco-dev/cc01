package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/freco-dev/cc01/core-server/access"
	"github.com/freco-dev/cc01/core-server/config"
	"github.com/freco-dev/cc01/core-server/events"
	"github.com/freco-dev/cc01/core-server/tunnel"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// Bu fayldagi yordamchilar boshqa test fayllaridagilardan mustaqil
// (nomlari "conn" bilan boshlanadi).

const connIOTimeout = 5 * time.Second

// connLoopback bir juft bog'langan loopback TCP ulanish qaytaradi.
func connLoopback(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-accepted
	if server == nil {
		t.Fatal("accept muvaffaqiyatsiz")
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	return server, client
}

func connReadFrame(t *testing.T, c net.Conn) *cc01v1.Frame {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(connIOTimeout))
	defer c.SetReadDeadline(time.Time{})
	frame, err := events.ReadFrame(c)
	if err != nil {
		t.Fatalf("freym o'qilmadi: %v", err)
	}
	return frame
}

func connReadExactly(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(connIOTimeout))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("%d bayt o'qilmadi: %v", n, err)
	}
	return buf
}

func connServer(limits access.Grant) *CC01Server {
	j := &CC01Server{
		config: config.Config{
			DomainName:       "cc01.test",
			MaxConsPerTunnel: 10,
		},
		authorizer: &access.AllowAll{Limits: limits},
		logOut:     io.Discard,
	}
	j.initRegistry()
	return j
}

// ───────────── C2: ko'prikdagi HTTP ulanishda o'qish muddati ─────────────

// servePublicConn Host'ni o'qish uchun qo'ygan 3 s muddat ko'prikdan
// oldin olib tashlanadi: aks holda Bind 3 s dan keyin ommaviy ulanishdan
// o'qishda timeout olib, ikkala tomonni yopardi (sekin javob, katta
// yuklama, SSE/WebSocket, keep-alive).
func TestServePublicConn_BridgedConnSurvivesIdle(t *testing.T) {
	j := connServer(access.Grant{})

	evSrv, evCli := connLoopback(t)
	const host = "idle.cc01.test"
	tn, err := tunnel.NewHTTP(host, evSrv, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tn.Close)
	tn.Open()
	if err := tn.WriteOpened(&cc01v1.TunnelOpened{Hostname: host}); err != nil {
		t.Fatal(err)
	}
	if connReadFrame(t, evCli).GetTunnelOpened() == nil {
		t.Fatal("TunnelOpened kutilgan edi")
	}
	j.httpTunnels[host] = tn

	pubSrv, pubCli := connLoopback(t)
	served := make(chan error, 1)
	go func() { served <- j.servePublicConn(pubSrv) }()

	request := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	if _, err := pubCli.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	received := connReadFrame(t, evCli).GetConnectionReceived()
	if received == nil {
		t.Fatal("ConnectionReceived kutilgan edi")
	}
	if err := <-served; err != nil {
		t.Fatalf("servePublicConn: %v", err)
	}

	// CLI kabi: xususiy serverga ulanib, ommaviy ulanish portini yuboramiz.
	private, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tn.PrivateServerPort()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = private.Close() })
	portBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBuf, uint16(received.GetClientPort()))
	if _, err := private.Write(portBuf); err != nil {
		t.Fatal(err)
	}
	if got := string(connReadExactly(t, private, len(request))); got != request {
		t.Fatalf("boshlang'ich bufer: %q", got)
	}

	// Ulanish Host muddatidan uzoqroq jim turadi (sekin backend).
	time.Sleep(publicHostTimeout + 750*time.Millisecond)

	const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	if _, err := private.Write([]byte(response)); err != nil {
		t.Fatalf("javob yozilmadi: %v", err)
	}
	if got := string(connReadExactly(t, pubCli, len(response))); got != response {
		t.Fatalf("javob: %q", got)
	}

	// Keep-alive: o'sha ulanishda keyingi so'rov ham o'tadi.
	if _, err := pubCli.Write([]byte(request)); err != nil {
		t.Fatalf("ikkinchi so'rov yozilmadi: %v", err)
	}
	if got := string(connReadExactly(t, private, len(request))); got != request {
		t.Fatalf("ikkinchi so'rov: %q", got)
	}
}

// ───────────── C1: o'qimay qo'ygan klient va boshqaruv kanali ─────────────

// connStallConn — boshqaruv kanalining server tomoni. stall yoqilgach
// Write yadro buferi to'lgandek turib qoladi va faqat yozish muddati
// yoki Close uni bo'shatadi (haqiqiy net.Conn kabi). Read va manzillar
// haqiqiy ulanishdan.
type connStallConn struct {
	net.Conn

	stall   atomic.Bool
	pending atomic.Int32

	mu       sync.Mutex
	deadline time.Time

	closeOnce sync.Once
	closed    chan struct{}
}

func (c *connStallConn) SetWriteDeadline(d time.Time) error {
	c.mu.Lock()
	c.deadline = d
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(d)
}

func (c *connStallConn) Write(p []byte) (int, error) {
	if !c.stall.Load() {
		return c.Conn.Write(p)
	}
	c.pending.Add(1)
	defer c.pending.Add(-1)
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *connStallConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// Klient boshqaruv kanalini yarim yopib (SHUT_WR) o'qishni to'xtatadi,
// edge esa shu payt unga ConnectionReceived yozayotgan bo'ladi. Klient
// ketgani aniqlanishi bilan kanal yopiladi va yozuvchi bo'shaydi:
// serveEventConn yozish muddatini (5 s) kutmasdan qaytadi, nom va
// tenant hisobi ro'yxatdan albatta o'chiriladi (aks holda SUBDOMAIN_BUSY
// va QUOTA_TUNNELS_EXCEEDED edge qayta ishga tushguncha qolardi).
func TestServeEventConn_HalfClosedClientReleasesStalledWriter(t *testing.T) {
	j := connServer(access.Grant{
		TenantID: "t1", Plan: "free", MaxTunnels: 1, MaxConnsPerTunnel: 10,
	})

	srv, cli := connLoopback(t)
	ev := &connStallConn{Conn: srv, closed: make(chan struct{})}
	t.Cleanup(func() { _ = ev.Close() })
	done := make(chan error, 1)
	go func() { done <- j.serveEventConn(ev) }()

	if err := events.WritePreamble(cli); err != nil {
		t.Fatal(err)
	}
	if err := events.WriteTunnelRequested(cli, &cc01v1.TunnelRequested{
		Protocol:  cc01v1.Protocol_PROTOCOL_HTTP,
		Subdomain: "stall",
	}); err != nil {
		t.Fatal(err)
	}
	opened := connReadFrame(t, cli).GetTunnelOpened()
	if opened == nil || opened.GetErrorCode() != "" {
		t.Fatalf("tunnel ochilmadi: %v", opened)
	}

	// Klient o'qishni to'xtatdi: keyingi freym kanalda turib qoladi.
	ev.stall.Store(true)
	pubSrv, pubCli := connLoopback(t)
	go func() { _ = j.servePublicConn(pubSrv) }()
	if _, err := pubCli.Write([]byte("GET / HTTP/1.1\r\nHost: stall.cc01.test\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(connIOTimeout)
	for ev.pending.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("ConnectionReceived yozuvi boshlanmadi")
		}
		time.Sleep(time.Millisecond)
	}

	if err := cli.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	// tunnel.EventWriteTimeout dan ancha kam: kanal klient ketishi bilan
	// yopilishi kerak, muddat tugashini kutmasdan.
	const budget = 2 * time.Second
	select {
	case <-done:
	case <-time.After(budget):
		t.Fatalf("serveEventConn %s ichida qaytmadi: kanalga yozuvchi bo'shatilmadi", budget)
	}

	j.tunnelsMx.RLock()
	httpN, tenants := len(j.httpTunnels), len(j.tenantTunnels)
	j.tunnelsMx.RUnlock()
	if httpN != 0 || tenants != 0 {
		t.Fatalf("ro'yxat tozalanmadi: http=%d tenant=%d", httpN, tenants)
	}
}
