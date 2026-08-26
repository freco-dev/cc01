package control

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

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

	// leader — rost bo'lsa ro'yxatga oladi, aks holda
	// NOT_LEADER qaytaradi.
	leader bool

	// fail — bo'sh bo'lmasa Register shu xatoni qaytaradi
	// (NOT_LEADER emas).
	fail error

	// calls — nechta Register chaqiruvi kelgani.
	calls int
}

func (f *fakeCP) Register(
	context.Context, *cc01v1.RegisterRequest,
) (*cc01v1.RegisterResponse, error) {
	f.calls++

	if f.fail != nil {
		return nil, f.fail
	}

	if !f.leader {
		st := status.New(codes.Unavailable, "bu node lider emas")
		detail, err := st.WithDetails(&errdetails.ErrorInfo{
			Reason: "NOT_LEADER",
			Domain: "cc01.control",
		})
		if err != nil {
			return nil, st.Err()
		}
		return nil, detail.Err()
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
