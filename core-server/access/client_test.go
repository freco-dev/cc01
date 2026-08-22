package access

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// fakeAccessServer — access-server o'rniga sinov uchun.
type fakeAccessServer struct {
	cc01v1.UnimplementedAccessInternalServiceServer

	calls    atomic.Int32
	response *cc01v1.AuthorizeTunnelResponse
	err      error
}

func (f *fakeAccessServer) AuthorizeTunnel(
	_ context.Context,
	_ *cc01v1.AuthorizeTunnelRequest,
) (*cc01v1.AuthorizeTunnelResponse, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.response, nil
}

func newTestClient(t *testing.T, fake *fakeAccessServer, grace time.Duration) *Client {
	t.Helper()

	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	cc01v1.RegisterAccessInternalServiceServer(server, fake)

	go func() { _ = server.Serve(listener) }()

	client, err := Dial(Options{
		Address: "passthrough:///bufnet",
		Timeout: time.Second,
		Grace:   grace,
		DialOptions: []grpc.DialOption{
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.DialContext(ctx)
			}),
		},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() {
		_ = client.Close()
		server.Stop()
	})
	return client
}

func grantResponse(subdomain string, maxConns uint32, ttl uint32) *cc01v1.AuthorizeTunnelResponse {
	return &cc01v1.AuthorizeTunnelResponse{
		Result: &cc01v1.AuthorizeTunnelResponse_Grant{
			Grant: &cc01v1.Grant{
				UserId:    42,
				TenantId:  "t_abc123",
				Plan:      "pro",
				Subdomain: subdomain,
				LeaseTtlS: ttl,
				Limits: &cc01v1.Limits{
					MaxTunnels:        10,
					MaxConnsPerTunnel: maxConns,
					BandwidthBps:      1_000_000_000,
				},
			},
		},
	}
}

func TestAuthorize_ReturnsGrant(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	client := newTestClient(t, fake, time.Minute)

	grant, err := client.Authorize(context.Background(), Request{Token: "tok", Subdomain: "myapp"})
	if err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}

	if grant.Subdomain != "myapp" {
		t.Errorf("subdomain: %q olindi", grant.Subdomain)
	}
	if grant.MaxConnsPerTunnel != 128 {
		t.Errorf("max_conns: %d olindi", grant.MaxConnsPerTunnel)
	}
	if grant.TenantID != "t_abc123" {
		t.Errorf("tenant: %q olindi", grant.TenantID)
	}
	if grant.LeaseTTL != time.Minute {
		t.Errorf("lease: %s olindi", grant.LeaseTTL)
	}
}

func TestAuthorize_MapsDenialCode(t *testing.T) {
	fake := &fakeAccessServer{
		response: &cc01v1.AuthorizeTunnelResponse{
			Result: &cc01v1.AuthorizeTunnelResponse_Denial{
				Denial: &cc01v1.Denial{
					Code:    cc01v1.DenialCode_DENIAL_CODE_SUBDOMAIN_NOT_OWNED,
					Message: "boshqa hisobga tegishli",
				},
			},
		},
	}
	client := newTestClient(t, fake, time.Minute)

	_, err := client.Authorize(context.Background(), Request{Token: "tok", Subdomain: "myapp"})

	var denial *Denial
	if !errors.As(err, &denial) {
		t.Fatalf("Denial kutilgan edi, olindi: %v", err)
	}
	// Proto prefiksi olib tashlanishi kerak.
	if denial.Code != "SUBDOMAIN_NOT_OWNED" {
		t.Errorf("kod: %q olindi", denial.Code)
	}
}

// Kesh: lease muddati ichida ikkinchi so'rov serverga bormasligi kerak.
func TestAuthorize_CachesWithinLease(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	client := newTestClient(t, fake, time.Minute)

	req := Request{Token: "tok", Subdomain: "myapp"}
	for range 3 {
		if _, err := client.Authorize(context.Background(), req); err != nil {
			t.Fatalf("kutilmagan xato: %v", err)
		}
	}

	if got := fake.calls.Load(); got != 1 {
		t.Errorf("serverga 1 marta murojaat kutilgan, %d bo'ldi", got)
	}
}

// Har xil token — har xil kesh yozuvi. Aks holda bir foydalanuvchining
// ruxsati boshqasiga o'tib ketardi.
func TestAuthorize_CacheIsPerToken(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	client := newTestClient(t, fake, time.Minute)

	_, _ = client.Authorize(context.Background(), Request{Token: "tok-a", Subdomain: "myapp"})
	_, _ = client.Authorize(context.Background(), Request{Token: "tok-b", Subdomain: "myapp"})

	if got := fake.calls.Load(); got != 2 {
		t.Errorf("2 ta murojaat kutilgan, %d bo'ldi", got)
	}
}

// Fail-static: AP yiqilgan, lekin kesh'da yaroqli yozuv bor → ruxsat beriladi
// (ARCHITECTURE.md §3.4.3).
func TestAuthorize_FailStaticUsesCacheWhenServerDown(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 1)}
	client := newTestClient(t, fake, time.Hour)

	req := Request{Token: "tok", Subdomain: "myapp"}
	if _, err := client.Authorize(context.Background(), req); err != nil {
		t.Fatalf("birinchi so'rov: %v", err)
	}

	// Lease tugadi va server yiqildi.
	client.expireFreshness(cacheKey(req))
	fake.err = status.Error(codes.Unavailable, "server yo'q")

	grant, err := client.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("fail-static ishlashi kerak edi: %v", err)
	}
	if grant.Subdomain != "myapp" {
		t.Errorf("kesh'dagi ruxsat kutilgan, olindi: %+v", grant)
	}
}

// Fail-static grace tugagach — rad etiladi. Deny-by-default.
func TestAuthorize_DeniesWhenServerDownAndGraceExpired(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 1)}
	client := newTestClient(t, fake, time.Hour)

	req := Request{Token: "tok", Subdomain: "myapp"}
	if _, err := client.Authorize(context.Background(), req); err != nil {
		t.Fatalf("birinchi so'rov: %v", err)
	}

	client.expireEntry(cacheKey(req))
	fake.err = status.Error(codes.Unavailable, "server yo'q")

	if _, err := client.Authorize(context.Background(), req); err == nil {
		t.Fatal("grace tugagach rad etilishi kerak edi")
	}
}

// Kesh butunlay bo'sh va server yiqilgan — hech qanday ruxsat berilmasligi shart.
func TestAuthorize_DeniesWhenServerDownAndCacheCold(t *testing.T) {
	fake := &fakeAccessServer{err: status.Error(codes.Unavailable, "server yo'q")}
	client := newTestClient(t, fake, time.Hour)

	_, err := client.Authorize(context.Background(), Request{Token: "tok", Subdomain: "myapp"})
	if err == nil {
		t.Fatal("rad etilishi kerak edi")
	}

	var denial *Denial
	if errors.As(err, &denial) {
		t.Error("tarmoq xatosi Denial sifatida ko'rsatilmasligi kerak")
	}
}

// Rad javobi keshlanmaydi: subdomain bo'shatilsa yoki token qayta
// yaratilsa, o'zgarish darhol kuchga kirishi kerak.
func TestAuthorize_DoesNotCacheDenials(t *testing.T) {
	fake := &fakeAccessServer{
		response: &cc01v1.AuthorizeTunnelResponse{
			Result: &cc01v1.AuthorizeTunnelResponse_Denial{
				Denial: &cc01v1.Denial{Code: cc01v1.DenialCode_DENIAL_CODE_SUBDOMAIN_BUSY},
			},
		},
	}
	client := newTestClient(t, fake, time.Minute)

	req := Request{Token: "tok", Subdomain: "myapp"}
	_, _ = client.Authorize(context.Background(), req)
	_, _ = client.Authorize(context.Background(), req)

	if got := fake.calls.Load(); got != 2 {
		t.Errorf("rad javobi keshlanmasligi kerak: %d murojaat", got)
	}
}

func TestAllowAll_EchoesRequestedSubdomain(t *testing.T) {
	authorizer := &AllowAll{Limits: Grant{MaxConnsPerTunnel: 24, Plan: "disabled"}}

	grant, err := authorizer.Authorize(context.Background(), Request{Subdomain: "anything"})
	if err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}
	if grant.Subdomain != "anything" {
		t.Errorf("subdomain: %q olindi", grant.Subdomain)
	}
	if grant.MaxConnsPerTunnel != 24 {
		t.Errorf("limit: %d olindi", grant.MaxConnsPerTunnel)
	}
}
