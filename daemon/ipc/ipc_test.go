package ipc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/engine"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/tun"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// fakeDevice — TUN o'rniga; IPC testlariga haqiqiy qurilma kerak emas.
type fakeDevice struct{ closed chan struct{} }

func newFakeDevice() *fakeDevice { return &fakeDevice{closed: make(chan struct{})} }

func (d *fakeDevice) Name() string   { return "cc0test" }
func (d *fakeDevice) BatchSize() int { return 4 }

func (d *fakeDevice) NewBuffers() ([][]byte, []int) {
	bufs := make([][]byte, 4)
	for i := range bufs {
		bufs[i] = make([]byte, tun.Offset+tun.DefaultMTU)
	}
	return bufs, make([]int, 4)
}

func (d *fakeDevice) Read([][]byte, []int, int) (int, error) {
	<-d.closed
	return 0, errors.New("yopilgan")
}

func (d *fakeDevice) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

func (d *fakeDevice) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

func startDaemon(t *testing.T) (cc01v1.DaemonServiceClient, *engine.Engine) {
	t.Helper()

	identity, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	bind, err := conn.Open(0)
	if err != nil {
		t.Fatalf("soket: %v", err)
	}

	datapath, err := engine.New(engine.Config{
		Identity: identity,
		Device:   newFakeDevice(),
		Bind:     bind,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	datapath.Start()

	service := NewService(datapath, Info{
		NodeID:       "node-abc123",
		Hostname:     "laptop",
		Tenant:       "t1",
		Address:      "fd00:cc01::1/128",
		ControlPlane: "cp.example:8443",
		Endpoints:    []string{"203.0.113.7:51820"},
		Version:      "test",
		RelayID:      func() string { return "relay-1" },
	})

	socket := shortSocket(t)

	server, err := Listen(socket, service, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go server.Serve()

	conn, err := Dial(socket)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
		_ = server.Close()
		_ = datapath.Close()
	})

	return cc01v1.NewDaemonServiceClient(conn), datapath
}

// ═══════════════ Soket ═══════════════

// Soket tarmoqqa emas, faylga bog'lanadi va faqat egasi/guruh
// kira oladi.
func TestListen_SocketPermissions(t *testing.T) {
	socket := shortSocket(t)

	server, err := Listen(socket, &Service{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer server.Close()

	info, err := os.Stat(socket)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		t.Error("soket yaratilmadi")
	}
	if perm := info.Mode().Perm(); perm != SocketMode {
		t.Errorf("ruxsatlar %o kutilgan, %o olindi", SocketMode, perm)
	}
	// Boshqalar kira olmasligi kerak.
	if info.Mode().Perm()&0o007 != 0 {
		t.Errorf("boshqalar uchun ruxsat ochiq: %o", info.Mode().Perm())
	}
}

// Demon SIGKILL bilan tugasa soket fayli orqada qoladi — keyingi
// ishga tushishda u to'sqinlik qilmasligi kerak
// (DEV_SPEC §7.1 majburiy stsenariy 8).
func TestListen_ReplacesStaleSocket(t *testing.T) {
	socket := shortSocket(t)

	first, err := Listen(socket, &Service{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("birinchi Listen: %v", err)
	}
	// Close CHAQIRILMAYDI — SIGKILL ni taqlid qilamiz.
	_ = first.listener.Close()

	second, err := Listen(socket, &Service{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("eskirgan soket to'sqinlik qildi: %v", err)
	}
	_ = second.Close()
}

// Soket bo'lmagan faylni o'chirib yubormasligi kerak.
func TestListen_RefusesToReplaceRegularFile(t *testing.T) {
	path := filepath.Join(filepath.Dir(shortSocket(t)), "muhim.txt")
	if err := os.WriteFile(path, []byte("ma'lumot"), 0o600); err != nil {
		t.Fatalf("fayl yaratish: %v", err)
	}

	if _, err := Listen(path, &Service{}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("oddiy faylni almashtirishga urindi")
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("fayl o'chirilib ketdi: %v", err)
	}
}

func TestClose_RemovesSocket(t *testing.T) {
	socket := shortSocket(t)

	server, err := Listen(socket, &Service{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Error("soket fayli qoldi")
	}

	// Idempotent.
	if err := server.Close(); err != nil {
		t.Errorf("ikkinchi Close: %v", err)
	}
}

// ═══════════════ Status ═══════════════

func TestStatus_ReportsDaemonInfo(t *testing.T) {
	client, datapath := startDaemon(t)

	response, err := client.Status(t.Context(), &cc01v1.StatusRequest{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	if !response.GetConnected() {
		t.Error("ulangan deb ko'rsatilishi kerak")
	}
	if response.GetNodeId() != "node-abc123" {
		t.Errorf("node: %q", response.GetNodeId())
	}
	if response.GetHostname() != "laptop" {
		t.Errorf("hostname: %q", response.GetHostname())
	}
	if response.GetInterface() != "cc0test" {
		t.Errorf("interfeys: %q", response.GetInterface())
	}
	if response.GetListenPort() != uint32(datapath.ListenPort()) {
		t.Errorf("port: %d", response.GetListenPort())
	}
	if response.GetRelayId() != "relay-1" {
		t.Errorf("relay: %q", response.GetRelayId())
	}
	if response.GetPublicKey() == "" {
		t.Error("public kalit bo'sh")
	}
}

func TestWatchStatus_SendsImmediatelyThenPeriodically(t *testing.T) {
	client, _ := startDaemon(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	stream, err := client.WatchStatus(ctx, &cc01v1.WatchStatusRequest{IntervalSeconds: 1})
	if err != nil {
		t.Fatalf("WatchStatus: %v", err)
	}

	// Birinchi javob darhol kelishi kerak — klient kutmasligi kerak.
	start := time.Now()
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("birinchi javob: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("birinchi javob %s kechikdi", elapsed)
	}

	if _, err := stream.Recv(); err != nil {
		t.Fatalf("ikkinchi javob: %v", err)
	}
}

// ═══════════════ Peers ═══════════════

func TestPeers_ReportsPathAndState(t *testing.T) {
	client, datapath := startDaemon(t)

	other, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	if _, err := datapath.AddPeer(other.PublicKey(),
		[]netip.Prefix{netip.MustParsePrefix("fd00:cc01::2/128")},
		netip.MustParseAddrPort("203.0.113.9:51820")); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	response, err := client.Peers(t.Context(), &cc01v1.PeersRequest{})
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}

	if len(response.GetPeers()) != 1 {
		t.Fatalf("1 peer kutilgan, %d olindi", len(response.GetPeers()))
	}

	peer := response.GetPeers()[0]
	if peer.GetPublicKey() != other.PublicKey().String() {
		t.Errorf("public kalit: %q", peer.GetPublicKey())
	}
	if len(peer.GetNodeId()) != 64 {
		t.Errorf("node_id SHA-256 hex bo'lishi kerak: %q", peer.GetNodeId())
	}
	if peer.GetOnline() {
		t.Error("sessiyasiz peer online bo'lmasligi kerak")
	}
	if peer.GetPathState() == "" {
		t.Error("yo'l holati bo'sh")
	}
}

// Sessiyasi bo'lmagan peerlar `--online` bilan chiqmasligi kerak.
func TestPeers_OnlineFilter(t *testing.T) {
	client, datapath := startDaemon(t)

	other, _ := noise.GenerateIdentity()
	if _, err := datapath.AddPeer(other.PublicKey(),
		[]netip.Prefix{netip.MustParsePrefix("fd00:cc01::2/128")},
		netip.MustParseAddrPort("203.0.113.9:51820")); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	response, err := client.Peers(t.Context(), &cc01v1.PeersRequest{OnlineOnly: true})
	if err != nil {
		t.Fatalf("Peers: %v", err)
	}

	if len(response.GetPeers()) != 0 {
		t.Errorf("offline peer filtrlanishi kerak, %d olindi", len(response.GetPeers()))
	}
}

// ═══════════════ Doctor ═══════════════

func TestDoctor_ReportsChecksWithRemediation(t *testing.T) {
	client, _ := startDaemon(t)

	response, err := client.Doctor(t.Context(), &cc01v1.DoctorRequest{})
	if err != nil {
		t.Fatalf("Doctor: %v", err)
	}

	if len(response.GetChecks()) == 0 {
		t.Fatal("tekshiruvlar bo'sh")
	}

	for _, check := range response.GetChecks() {
		if check.GetName() == "" {
			t.Error("tekshiruv nomi bo'sh")
		}
		if check.GetStatus() == cc01v1.Check_STATUS_UNSPECIFIED {
			t.Errorf("%s: holat belgilanmagan", check.GetName())
		}

		// Muammo bo'lsa uni QANDAY tuzatish ham aytilishi kerak —
		// foydalanuvchi hujjat qidirmasligi kerak.
		if check.GetStatus() != cc01v1.Check_STATUS_OK && check.GetRemediation() == "" {
			t.Errorf("%s: muammo bor, lekin tuzatish yo'li yo'q", check.GetName())
		}
	}
}

func TestRunChecks_AlwaysReturnsChecks(t *testing.T) {
	checks := RunChecks()

	if len(checks) < 3 {
		t.Errorf("kamida 3 ta tekshiruv kutilgan, %d olindi", len(checks))
	}

	names := make(map[string]bool, len(checks))
	for _, check := range checks {
		if names[check.GetName()] {
			t.Errorf("takroriy tekshiruv: %s", check.GetName())
		}
		names[check.GetName()] = true
	}
}

// shortSocket qisqa soket yo'lini beradi.
//
// `t.TempDir()` test nomini yo'lga qo'shadi va macOS'dagi 104 baytlik
// chegaradan oshib ketadi.
func shortSocket(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "cc01")
	if err != nil {
		t.Fatalf("vaqtinchalik papka: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	return filepath.Join(dir, "d.sock")
}

// Uzun yo'l tushunarli xato berishi kerak, `invalid argument` emas.
func TestListen_RejectsOverlongPath(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "cc01")
	if err != nil {
		t.Fatalf("papka: %v", err)
	}
	defer os.RemoveAll(dir)

	long := filepath.Join(dir, strings.Repeat("u", 200)+".sock")

	_, err = Listen(long, &Service{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("uzun yo'l rad etilishi kerak edi")
	}
	if !strings.Contains(err.Error(), "juda uzun") {
		t.Errorf("sabab ko'rsatilishi kerak, olindi: %v", err)
	}
}
