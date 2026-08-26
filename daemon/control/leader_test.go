package control

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/freco-dev/cc01/daemon/noise"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// Klasterda manzil berish Raft yozuvi — uni faqat lider bajara
// oladi. Bu testlar klient liderni o'zi topa olishini tekshiradi.

// fakeCP — Register'ga oldindan belgilangan javob beruvchi CP.
type fakeCP struct {
	cc01v1.UnimplementedControlServiceServer

	mu sync.Mutex

	// leader — rost bo'lsa ro'yxatga oladi, aks holda
	// NOT_LEADER qaytaradi.
	leader bool

	// fail — bo'sh bo'lmasa Register shu xatoni qaytaradi
	// (NOT_LEADER emas).
	fail error

	// calls — nechta Register chaqiruvi kelgani.
	calls int

	// heartbeats — nechta Heartbeat kelgani.
	heartbeats int
}

func (f *fakeCP) setLeader(leader bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leader = leader
}

func (f *fakeCP) beats() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeats
}

// Heartbeat ham Raft yozuvi — faqat liderda ishlaydi.
func (f *fakeCP) Heartbeat(
	context.Context, *cc01v1.HeartbeatRequest,
) (*cc01v1.HeartbeatResponse, error) {
	f.mu.Lock()
	leader := f.leader
	f.heartbeats++
	f.mu.Unlock()

	if !leader {
		return nil, notLeaderError()
	}
	return &cc01v1.HeartbeatResponse{}, nil
}

// notLeaderError haqiqiy CP bilan bir xil javob yasaydi.
func notLeaderError() error {
	st := status.New(codes.Unavailable, "bu node lider emas")
	detail, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: "NOT_LEADER",
		Domain: "cc01.control",
	})
	if err != nil {
		return st.Err()
	}
	return detail.Err()
}

func (f *fakeCP) Register(
	context.Context, *cc01v1.RegisterRequest,
) (*cc01v1.RegisterResponse, error) {
	f.mu.Lock()
	f.calls++
	leader, fail := f.leader, f.fail
	f.mu.Unlock()

	if fail != nil {
		return nil, fail
	}

	if !leader {
		return nil, notLeaderError()
	}

	return &cc01v1.RegisterResponse{
		NodeId:             "node-1",
		Address:            "2a0e:1::5/128",
		TenantCidr:         "2a0e:1::/64",
		HeartbeatIntervalS: 30,
	}, nil
}

// startCP soxta CP ni ishga tushiradi va manzilini qaytaradi.
func startCP(t *testing.T, cp *fakeCP) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tinglash: %v", err)
	}

	server := grpc.NewServer()
	cc01v1.RegisterControlServiceServer(server, cp)

	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	return listener.Addr().String()
}

func leaderTestClient(t *testing.T, addresses string) *Client {
	t.Helper()

	identity, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	client, err := Dial(Config{
		Address:  addresses,
		Identity: identity,
		Tenant:   "t1",
		Insecure: true,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return client
}

// Follower'ga tushgan klient liderni topib olishi kerak.
func TestRegister_FindsLeaderAmongFollowers(t *testing.T) {
	follower := &fakeCP{}
	leader := &fakeCP{leader: true}

	followerAddr := startCP(t, follower)
	leaderAddr := startCP(t, leader)

	// Ataylab follower birinchi.
	client := leaderTestClient(t, followerAddr+","+leaderAddr)

	registration, err := client.Register(context.Background())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if registration.NodeID != "node-1" {
		t.Errorf("node %q", registration.NodeID)
	}

	if follower.calls != 1 {
		t.Errorf("follower %d marta chaqirildi, 1 kutilgan edi", follower.calls)
	}
	if leader.calls != 1 {
		t.Errorf("lider %d marta chaqirildi, 1 kutilgan edi", leader.calls)
	}

	// Ulanish liderda qolishi kerak: heartbeat va NetworkMap
	// oqimi ham o'sha nodedan boradi.
	if got := client.Address(); got != leaderAddr {
		t.Errorf("ulanish %s da qoldi, lider %s", got, leaderAddr)
	}
}

// Hamma follower bo'lsa xato aniq bo'lishi kerak.
func TestRegister_AllFollowersFails(t *testing.T) {
	first := startCP(t, &fakeCP{})
	second := startCP(t, &fakeCP{})

	client := leaderTestClient(t, first+","+second)

	_, err := client.Register(context.Background())
	if err == nil {
		t.Fatal("xato kutilgan edi")
	}
	if !strings.Contains(err.Error(), "hech biri lider emas") {
		t.Errorf("xato tushunarsiz: %v", err)
	}
}

// Lider bilan bog'liq bo'lmagan xatoda manzil aylantirilmasligi
// kerak — aks holda haqiqiy nosozlik butun ro'yxat bo'ylab
// takrorlanib, sababi ko'milib ketardi.
func TestRegister_OtherErrorDoesNotRotate(t *testing.T) {
	broken := &fakeCP{
		fail: status.Error(codes.PermissionDenied, "token noto'g'ri"),
	}
	next := &fakeCP{leader: true}

	brokenAddr := startCP(t, broken)
	nextAddr := startCP(t, next)

	client := leaderTestClient(t, brokenAddr+","+nextAddr)

	_, err := client.Register(context.Background())
	if err == nil {
		t.Fatal("xato kutilgan edi")
	}
	if !strings.Contains(err.Error(), "token noto'g'ri") {
		t.Errorf("asl sabab yo'qoldi: %v", err)
	}

	// Eng muhimi: keyingi CP ga UMUMAN borilmasligi kerak. Aks
	// holda noto'g'ri token butun ro'yxat bo'ylab takrorlanib,
	// operator sababni topolmasdi.
	if next.calls != 0 {
		t.Errorf("ikkinchi CP %d marta chaqirildi, 0 kutilgan edi", next.calls)
	}
	if client.Address() != brokenAddr {
		t.Errorf("ulanish aylantirildi: %s", client.Address())
	}
}

// Unavailable bo'lsa-yu NOT_LEADER tafsiloti bo'lmasa, bu boshqa
// nosozlik — aylantirilmasligi kerak.
func TestIsNotLeader_RequiresReason(t *testing.T) {
	plain := status.Error(codes.Unavailable, "ulanib bo'lmadi")
	if isNotLeader(plain) {
		t.Error("tafsilotsiz Unavailable NOT_LEADER deb hisoblandi")
	}

	st, err := status.New(codes.Unavailable, "boshqa sabab").WithDetails(
		&errdetails.ErrorInfo{Reason: "QUOTA_EXCEEDED", Domain: "cc01.control"})
	if err != nil {
		t.Fatalf("tafsilot: %v", err)
	}
	if isNotLeader(st.Err()) {
		t.Error("boshqa sabab NOT_LEADER deb hisoblandi")
	}
}

// Bo'sh manzil aniq xato berishi kerak.
func TestSplitAddresses(t *testing.T) {
	cases := map[string][]string{
		"a:1":         {"a:1"},
		"a:1,b:2":     {"a:1", "b:2"},
		" a:1 , b:2 ": {"a:1", "b:2"},
		"a:1,,b:2":    {"a:1", "b:2"},
	}

	for input, want := range cases {
		got, err := splitAddresses(input)
		if err != nil {
			t.Errorf("%q: %v", input, err)
			continue
		}
		if len(got) != len(want) {
			t.Errorf("%q → %v, %v kutilgan edi", input, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q → %v, %v kutilgan edi", input, got, want)
				break
			}
		}
	}

	if _, err := splitAddresses("  ,  "); err == nil {
		t.Error("bo'sh manzil qabul qilindi")
	}
}

// Bitta manzil berilganda ham xato tushunarli bo'lishi kerak.
func TestRegister_SingleAddressFollower(t *testing.T) {
	follower := &fakeCP{}
	client := leaderTestClient(t, startCP(t, follower))

	_, err := client.Register(context.Background())
	if err == nil {
		t.Fatal("xato kutilgan edi")
	}
	if !strings.Contains(err.Error(), "hech biri lider emas") {
		t.Errorf("xato tushunarsiz: %v", err)
	}

	// Bir marta so'raladi, o'ziga qayta ulanilmaydi.
	if follower.calls != 1 {
		t.Errorf("%d marta chaqirildi, 1 kutilgan edi", follower.calls)
	}
}

// Lider almashganda heartbeat yangi liderni topishi kerak.
//
// Topa olmasa node jimgina muddati o'tib, ro'yxatdan tushib
// ketardi — va buni hech kim sezmasdi, chunki NetworkMap oqimi
// hali ishlab turgan bo'lardi.
func TestHeartbeat_FollowsNewLeader(t *testing.T) {
	first := &fakeCP{leader: true}
	second := &fakeCP{}

	firstAddr := startCP(t, first)
	secondAddr := startCP(t, second)

	client := leaderTestClient(t, firstAddr+","+secondAddr)

	if _, err := client.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if client.Address() != firstAddr {
		t.Fatalf("birinchi CP da bo'lishi kerak edi: %s", client.Address())
	}

	// Lider almashdi.
	first.setLeader(false)
	second.setLeader(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go client.heartbeatLoop(ctx, 50*time.Millisecond)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if client.Address() == secondAddr && second.beats() > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Errorf("yangi lider topilmadi: manzil=%s, eski CP=%d beat, yangi CP=%d beat",
		client.Address(), first.beats(), second.beats())
}

// Sog' ulanishda aylanmaslik kerak.
//
// Heartbeat ham, NetworkMap oqimi ham aylantira oladi. Guard
// bo'lmasa ular bir-birini quvib, ulanishni manzillar bo'ylab
// cheksiz surib yurardi — va node hech qachon barqaror CP da
// qolmasdi.
func TestRotateOnFailure_KeepsHealthyConnection(t *testing.T) {
	leader := &fakeCP{leader: true}
	other := &fakeCP{leader: true}

	leaderAddr := startCP(t, leader)
	client := leaderTestClient(t, leaderAddr+","+startCP(t, other))

	if _, err := client.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	before := client.Address()
	for range 5 {
		client.rotateOnFailure()
	}

	if got := client.Address(); got != before {
		t.Errorf("sog' ulanish almashtirildi: %s → %s", before, got)
	}
}

// CP yiqilsa esa aylanish SHART.
func TestRotateOnFailure_LeavesDeadCP(t *testing.T) {
	dead := &fakeCP{leader: true}
	alive := &fakeCP{leader: true}

	deadAddr, stopDead := startCPStoppable(t, dead)
	aliveAddr := startCP(t, alive)

	client := leaderTestClient(t, deadAddr+","+aliveAddr)
	if _, err := client.Register(context.Background()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	stopDead()

	// Ulanish nosozlikni sezishi uchun bir chaqiruv qilamiz.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = client.svc().Heartbeat(context.Background(),
			&cc01v1.HeartbeatRequest{NodeId: "x"})
		client.rotateOnFailure()
		if client.Address() == aliveAddr {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Errorf("o'lik CP da qolib ketdi: %s", client.Address())
}

// startCPStoppable — to'xtatib bo'ladigan soxta CP.
func startCPStoppable(t *testing.T, cp *fakeCP) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tinglash: %v", err)
	}

	server := grpc.NewServer()
	cc01v1.RegisterControlServiceServer(server, cp)
	go func() { _ = server.Serve(listener) }()

	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			server.Stop()
		}
	}
	t.Cleanup(stop)

	return listener.Addr().String(), stop
}
