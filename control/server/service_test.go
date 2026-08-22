package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/freco-dev/cc01/control/ipam"
	"github.com/freco-dev/cc01/control/registry"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const testToken = "sinov-siri"

func newTestServer(t *testing.T, authToken string) cc01v1.ControlServiceClient {
	t.Helper()

	allocator, err := ipam.New(ipam.Options{Store: ipam.NewMemoryStore()})
	if err != nil {
		t.Fatalf("ipam: %v", err)
	}

	service, err := New(Config{
		Registry:     registry.New(registry.Options{}),
		Allocator:    allocator,
		TenantPrefix: netip.MustParsePrefix("fd00:cc01:c0de::/64"),
		AuthToken:    authToken,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	cc01v1.RegisterControlServiceServer(grpcServer, service)
	go func() { _ = grpcServer.Serve(listener) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
		grpcServer.Stop()
	})

	return cc01v1.NewControlServiceClient(conn)
}

func publicKey(seed byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func registerNode(t *testing.T, client cc01v1.ControlServiceClient, seed byte, hostname string) *cc01v1.RegisterResponse {
	t.Helper()

	response, err := client.Register(t.Context(), &cc01v1.RegisterRequest{
		PublicKey: publicKey(seed),
		Tenant:    "t1",
		Hostname:  hostname,
		Endpoints: []string{"10.0.0.1:51820"},
		AuthToken: testToken,
	})
	if err != nil {
		t.Fatalf("Register(%s): %v", hostname, err)
	}
	return response
}

// ═══════════════ Register ═══════════════

func TestRegister_AssignsAddressFromTenantPrefix(t *testing.T) {
	client := newTestServer(t, testToken)

	response := registerNode(t, client, 1, "laptop")

	address, err := netip.ParsePrefix(response.GetAddress())
	if err != nil {
		t.Fatalf("manzil parse: %v", err)
	}
	if address.Bits() != 128 {
		t.Errorf("/128 kutilgan, /%d olindi", address.Bits())
	}

	tenantNet := netip.MustParsePrefix("fd00:cc01:c0de::/64")
	if !tenantNet.Contains(address.Addr()) {
		t.Errorf("%v tenant prefiksi ichida emas", address)
	}
	if response.GetTenantCidr() != tenantNet.String() {
		t.Errorf("tenant CIDR: %q", response.GetTenantCidr())
	}
	if response.GetHeartbeatIntervalS() == 0 {
		t.Error("heartbeat oralig'i berilmadi")
	}
}

// Qayta ulanish odatiy hol — u yangi node ham, yangi manzil ham
// yaratmasligi kerak.
func TestRegister_IsIdempotent(t *testing.T) {
	client := newTestServer(t, testToken)

	first := registerNode(t, client, 1, "laptop")
	second := registerNode(t, client, 1, "laptop")

	if first.GetNodeId() != second.GetNodeId() {
		t.Errorf("node ID o'zgardi: %s → %s", first.GetNodeId(), second.GetNodeId())
	}
	if first.GetAddress() != second.GetAddress() {
		t.Errorf("manzil o'zgardi: %s → %s", first.GetAddress(), second.GetAddress())
	}
}

func TestRegister_RejectsBadAuthToken(t *testing.T) {
	client := newTestServer(t, testToken)

	_, err := client.Register(t.Context(), &cc01v1.RegisterRequest{
		PublicKey: publicKey(1),
		Tenant:    "t1",
		AuthToken: "noto'g'ri",
	})

	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Unauthenticated kutilgan, olindi: %v", err)
	}
}

// Sir bo'sh bo'lsa tekshiruv o'tkazib yuboriladi — bu oshkora
// tanlanadigan rejim.
func TestRegister_AuthDisabledAcceptsAnyToken(t *testing.T) {
	client := newTestServer(t, "")

	if _, err := client.Register(t.Context(), &cc01v1.RegisterRequest{
		PublicKey: publicKey(1),
		Tenant:    "t1",
		AuthToken: "nimadir",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func TestRegister_Validation(t *testing.T) {
	client := newTestServer(t, testToken)

	cases := []struct {
		name string
		req  *cc01v1.RegisterRequest
	}{
		{"kalit qisqa", &cc01v1.RegisterRequest{
			PublicKey: []byte{1, 2, 3}, Tenant: "t1", AuthToken: testToken,
		}},
		{"tenant yo'q", &cc01v1.RegisterRequest{
			PublicKey: publicKey(1), AuthToken: testToken,
		}},
		{"endpoint yaroqsiz", &cc01v1.RegisterRequest{
			PublicKey: publicKey(1), Tenant: "t1",
			Endpoints: []string{"axlat"}, AuthToken: testToken,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := client.Register(t.Context(), tc.req); status.Code(err) != codes.InvalidArgument {
				t.Errorf("InvalidArgument kutilgan, olindi: %v", err)
			}
		})
	}
}

// ═══════════════ WatchNetworkMap ═══════════════

func TestWatch_FirstResponseIsFullMap(t *testing.T) {
	client := newTestServer(t, testToken)

	alice := registerNode(t, client, 1, "alice")
	registerNode(t, client, 100, "bob")

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	stream, err := client.WatchNetworkMap(ctx, &cc01v1.WatchNetworkMapRequest{
		NodeId: alice.GetNodeId(), AuthToken: testToken,
	})
	if err != nil {
		t.Fatalf("WatchNetworkMap: %v", err)
	}

	netmap, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}

	if !netmap.GetFull() {
		t.Error("birinchi javob to'liq map bo'lishi kerak")
	}
	if netmap.GetSelf().GetNodeId() != alice.GetNodeId() {
		t.Errorf("self: %q", netmap.GetSelf().GetNodeId())
	}
	if len(netmap.GetPeers()) != 1 || netmap.GetPeers()[0].GetHostname() != "bob" {
		t.Errorf("bob peer sifatida kutilgan: %+v", netmap.GetPeers())
	}
}

// Yangi node qo'shilganda stream'dagi mavjud klientlar xabar olishi
// kerak — mesh aynan shu bilan avtomatik bo'ladi.
func TestWatch_PushesNewPeers(t *testing.T) {
	client := newTestServer(t, testToken)

	alice := registerNode(t, client, 1, "alice")

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	stream, err := client.WatchNetworkMap(ctx, &cc01v1.WatchNetworkMapRequest{
		NodeId: alice.GetNodeId(), AuthToken: testToken,
	})
	if err != nil {
		t.Fatalf("WatchNetworkMap: %v", err)
	}

	if _, err := stream.Recv(); err != nil {
		t.Fatalf("birinchi map: %v", err)
	}

	registerNode(t, client, 100, "bob")

	netmap, err := stream.Recv()
	if err != nil {
		t.Fatalf("delta: %v", err)
	}

	if len(netmap.GetPeers()) != 1 || netmap.GetPeers()[0].GetHostname() != "bob" {
		t.Errorf("bob kutilgan: %+v", netmap.GetPeers())
	}
	if netmap.GetPeers()[0].GetEndpoints()[0] != "10.0.0.1:51820" {
		t.Errorf("endpoint: %v", netmap.GetPeers()[0].GetEndpoints())
	}
}

func TestWatch_RejectsUnknownNode(t *testing.T) {
	client := newTestServer(t, testToken)

	stream, err := client.WatchNetworkMap(t.Context(), &cc01v1.WatchNetworkMapRequest{
		NodeId: "yoq", AuthToken: testToken,
	})
	if err != nil {
		t.Fatalf("WatchNetworkMap: %v", err)
	}

	if _, err := stream.Recv(); status.Code(err) != codes.NotFound {
		t.Fatalf("NotFound kutilgan, olindi: %v", err)
	}
}

func TestWatch_RejectsBadToken(t *testing.T) {
	client := newTestServer(t, testToken)

	alice := registerNode(t, client, 1, "alice")

	stream, err := client.WatchNetworkMap(t.Context(), &cc01v1.WatchNetworkMapRequest{
		NodeId: alice.GetNodeId(), AuthToken: "noto'g'ri",
	})
	if err != nil {
		t.Fatalf("WatchNetworkMap: %v", err)
	}

	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Unauthenticated kutilgan, olindi: %v", err)
	}
}

// ═══════════════ Heartbeat ═══════════════

func TestHeartbeat_ExtendsLease(t *testing.T) {
	client := newTestServer(t, testToken)

	alice := registerNode(t, client, 1, "alice")

	response, err := client.Heartbeat(t.Context(), &cc01v1.HeartbeatRequest{
		NodeId: alice.GetNodeId(), AuthToken: testToken,
	})
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	if response.GetLeaseExpiresAt() == 0 {
		t.Error("muddat qaytarilmadi")
	}
	if response.GetMapVersion() == 0 {
		t.Error("map versiyasi qaytarilmadi")
	}
}

// Node ro'yxatdan tushib qolgan bo'lsa, unga qayta ro'yxatdan o'tish
// kerakligini aniq aytish kerak.
func TestHeartbeat_UnknownNodeTellsToReregister(t *testing.T) {
	client := newTestServer(t, testToken)

	_, err := client.Heartbeat(t.Context(), &cc01v1.HeartbeatRequest{
		NodeId: "yoq", AuthToken: testToken,
	})

	if status.Code(err) != codes.NotFound {
		t.Fatalf("NotFound kutilgan, olindi: %v", err)
	}
}

// Tenant izolyatsiyasi gRPC qatlamida ham saqlanishi kerak.
func TestWatch_TenantIsolation(t *testing.T) {
	client := newTestServer(t, testToken)

	alice := registerNode(t, client, 1, "alice")

	if _, err := client.Register(t.Context(), &cc01v1.RegisterRequest{
		PublicKey: publicKey(200),
		Tenant:    "boshqa-tenant",
		Hostname:  "begona",
		AuthToken: testToken,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	stream, err := client.WatchNetworkMap(ctx, &cc01v1.WatchNetworkMapRequest{
		NodeId: alice.GetNodeId(), AuthToken: testToken,
	})
	if err != nil {
		t.Fatalf("WatchNetworkMap: %v", err)
	}

	netmap, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}

	if len(netmap.GetPeers()) != 0 {
		t.Errorf("begona tenant peerlari ko'rindi: %+v", netmap.GetPeers())
	}
}
