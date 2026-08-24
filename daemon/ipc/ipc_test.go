package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/engine"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/route"
	"github.com/freco-dev/cc01/daemon/session"
	"github.com/freco-dev/cc01/daemon/tun"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// fakeBackend — haqiqiy sessiya o'rniga: uni ko'tarish uchun CP,
// TUN va root kerak bo'lardi.
type fakeBackend struct {
	engine *engine.Engine

	mu      sync.Mutex
	up      bool
	upErr   error
	downErr error
	ups     int
	downs   int
}

func (b *fakeBackend) Status() (session.Status, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.up {
		return session.Status{}, false
	}

	status := session.Status{
		NodeID:       "node-abc123",
		Hostname:     "laptop",
		Tenant:       "t1",
		Address:      "fd00:cc01::1/128",
		ControlPlane: "cp.example:8443",
		RelayID:      "relay-1",
		Endpoints:    []string{"203.0.113.7:51820"},
		Routes:       route.Status{Synced: true, Count: 1},
		Since:        time.Now().Add(-time.Minute),
	}

	// Hayot sikli testlariga datapath kerak emas — ular faqat
	// ko'tarilgan/tushirilgan holatni tekshiradi.
	if b.engine != nil {
		status.PublicKey = b.engine.PublicKey()
		status.Interface = b.engine.InterfaceName()
		status.ListenPort = b.engine.ListenPort()
	}

	return status, true
}

func (b *fakeBackend) Peers() []engine.PeerSnapshot {
	b.mu.Lock()
	up := b.up
	b.mu.Unlock()

	if !up || b.engine == nil {
		return nil
	}
	return b.engine.Snapshot()
}

func (b *fakeBackend) Up(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.ups++
	if b.upErr != nil {
		return b.upErr
	}
	b.up = true
	return nil
}

func (b *fakeBackend) Down() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.downs++
	if b.downErr != nil {
		return b.downErr
	}
	b.up = false
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

	service := NewService(&fakeBackend{engine: datapath, up: true}, "test")

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
	checks := RunChecks(nil)

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

// startWithBackend testga backend ustidan nazorat beradi.
func startWithBackend(t *testing.T, backend *fakeBackend) cc01v1.DaemonServiceClient {
	t.Helper()

	socket := shortSocket(t)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	server, err := Listen(socket, NewService(backend, "test"), quiet)
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
	})

	return cc01v1.NewDaemonServiceClient(conn)
}

// Tushirilgan mesh ham javob berishi kerak: demon ishlayotgani va
// ulanmagani — bu ikki xil holat.
func TestStatus_ReportsDisconnectedWithoutError(t *testing.T) {
	client := startWithBackend(t, &fakeBackend{up: false})

	response, err := client.Status(context.Background(), &cc01v1.StatusRequest{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if response.GetConnected() {
		t.Error("connected=true, mesh tushirilgan bo'lsa ham")
	}
	if response.GetVersion() != "test" {
		t.Errorf("versiya yo'qolgan: %q", response.GetVersion())
	}
}

// Down ikkinchi marta chaqirilsa xato emas — talab bajarilgan.
func TestDown_IsIdempotent(t *testing.T) {
	backend := &fakeBackend{up: true}
	client := startWithBackend(t, backend)

	first, err := client.Down(context.Background(), &cc01v1.DownRequest{})
	if err != nil {
		t.Fatalf("birinchi Down: %v", err)
	}
	if first.GetAlreadyDown() {
		t.Error("birinchi Down already_down qaytardi")
	}

	second, err := client.Down(context.Background(), &cc01v1.DownRequest{})
	if err != nil {
		t.Fatalf("ikkinchi Down: %v", err)
	}
	if !second.GetAlreadyDown() {
		t.Error("ikkinchi Down already_down qaytarmadi")
	}

	// Ikkinchi chaqiruv backend'ga umuman bormasligi kerak.
	backend.mu.Lock()
	downs := backend.downs
	backend.mu.Unlock()

	if downs != 1 {
		t.Errorf("Down %d marta chaqirildi, 1 kutilgan edi", downs)
	}
}

// Up allaqachon ko'tarilgan bo'lsa ALREADY_EXISTS berishi kerak:
// jimgina e'tiborsiz qoldirish konfiguratsiya farqini yashirardi.
func TestUp_ReportsAlreadyUp(t *testing.T) {
	backend := &fakeBackend{up: true, upErr: session.ErrAlreadyUp}
	client := startWithBackend(t, backend)

	_, err := client.Up(context.Background(), &cc01v1.UpRequest{})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("ALREADY_EXISTS kutilgan edi, olindi: %v (%s)", err, status.Code(err))
	}
}

// Down dan keyin Up qayta ko'tarishi kerak.
func TestUpDown_Cycle(t *testing.T) {
	backend := &fakeBackend{up: true}
	client := startWithBackend(t, backend)

	if _, err := client.Down(context.Background(), &cc01v1.DownRequest{}); err != nil {
		t.Fatalf("Down: %v", err)
	}

	response, err := client.Status(context.Background(), &cc01v1.StatusRequest{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if response.GetConnected() {
		t.Fatal("Down dan keyin ham ulangan")
	}

	if _, err := client.Up(context.Background(), &cc01v1.UpRequest{}); err != nil {
		t.Fatalf("Up: %v", err)
	}

	response, err = client.Status(context.Background(), &cc01v1.StatusRequest{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !response.GetConnected() {
		t.Error("Up dan keyin ulanmagan")
	}
}

// Mesh tushirilganda marshrut tekshiruvi bo'lmasligi kerak — u
// mavjud bo'lmagan holat haqida gapirardi.
func TestDoctor_OmitsRouteCheckWhenDown(t *testing.T) {
	client := startWithBackend(t, &fakeBackend{up: false})

	response, err := client.Doctor(context.Background(), &cc01v1.DoctorRequest{})
	if err != nil {
		t.Fatalf("Doctor: %v", err)
	}

	for _, check := range response.GetChecks() {
		if check.GetName() == "marshrutlar" {
			t.Error("tushirilgan mesh uchun marshrut tekshiruvi berildi")
		}
	}
}

// Guruh yo'q bo'lsa aniq xato qaytishi kerak, "topilmadi" emas —
// chaqiruvchi buni halokatli emas deb ajratishi kerak.
func TestApplyOwnership_ReportsMissingGroup(t *testing.T) {
	socket := shortSocket(t)
	if err := os.WriteFile(socket, nil, 0o660); err != nil {
		t.Fatalf("fayl yaratish: %v", err)
	}

	err := applyOwnership(socket, "cc01-yoq-bunday-guruh")
	if !errors.Is(err, errGroupMissing) {
		t.Fatalf("errGroupMissing kutilgan edi, olindi: %v", err)
	}
}

// Bo'sh guruh — hech narsa qilinmaydi.
func TestApplyOwnership_EmptyGroupIsNoop(t *testing.T) {
	if err := applyOwnership("/bunday/yol/yoq", ""); err != nil {
		t.Fatalf("bo'sh guruh xato berdi: %v", err)
	}
}

// Mavjud guruhga o'rnatish ishlashi kerak. O'z guruhimizni
// ishlatamiz — u albatta bor va uni o'zgartirish uchun root shart emas.
func TestApplyOwnership_SetsExistingGroup(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skipf("joriy foydalanuvchi aniqlanmadi: %v", err)
	}

	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Skipf("guruh nomi aniqlanmadi: %v", err)
	}

	socket := shortSocket(t)
	if err := os.WriteFile(socket, nil, 0o660); err != nil {
		t.Fatalf("fayl yaratish: %v", err)
	}

	if err := applyOwnership(socket, group.Name); err != nil {
		t.Fatalf("applyOwnership: %v", err)
	}

	info, err := os.Stat(socket)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("bu platformada gid o'qib bo'lmaydi")
	}
	if fmt.Sprint(stat.Gid) != current.Gid {
		t.Errorf("gid %d, kutilgan %s", stat.Gid, current.Gid)
	}
}

// slogDiscard — testlarda log chiqishini yutadi.
func slogDiscard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
