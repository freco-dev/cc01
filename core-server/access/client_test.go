package access

import (
	"context"
	"errors"
	"net"
	"sync"
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
//
// renewal bayrog'ini e'tiborsiz qoldiradi — ya'ni eski AP kabi ham ishlaydi.
// response/err va oxirgi so'rov mu ostida: testlar ularni RPC davomida
// o'zgartiradi (-race toza bo'lishi uchun).
type fakeAccessServer struct {
	cc01v1.UnimplementedAccessInternalServiceServer

	calls atomic.Int32

	mu        sync.Mutex
	response  *cc01v1.AuthorizeTunnelResponse
	err       error
	delay     time.Duration
	lastReq   *cc01v1.AuthorizeTunnelRequest
	handledAt time.Time

	// ReportUsage (usage_test.go): olingan so'rovlar, xato va qabul
	// qilinganlar soni (nil — hammasi).
	usageReqs     []*cc01v1.ReportUsageRequest
	usageErr      error
	usageAccepted func(n int) uint32
}

func (f *fakeAccessServer) AuthorizeTunnel(
	_ context.Context,
	req *cc01v1.AuthorizeTunnelRequest,
) (*cc01v1.AuthorizeTunnelResponse, error) {
	f.calls.Add(1)

	f.mu.Lock()
	f.lastReq = req
	f.handledAt = time.Now()
	delay, response, err := f.delay, f.response, f.err
	f.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (f *fakeAccessServer) set(response *cc01v1.AuthorizeTunnelResponse, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.response, f.err = response, err
}

func (f *fakeAccessServer) last() (*cc01v1.AuthorizeTunnelRequest, time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq, f.handledAt
}

func newTestClient(t *testing.T, fake *fakeAccessServer, grace time.Duration) *Client {
	t.Helper()
	return newTestClientWith(t, fake, Options{Grace: grace})
}

func newTestClientWith(t *testing.T, fake *fakeAccessServer, opts Options) *Client {
	t.Helper()

	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	cc01v1.RegisterAccessInternalServiceServer(server, fake)

	go func() { _ = server.Serve(listener) }()

	opts.Address = "passthrough:///localhost:0" // bufconn; loopback — shifrsiz ruxsat etilgan
	if opts.Timeout == 0 {
		opts.Timeout = time.Second
	}
	opts.DialOptions = []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
	}

	client, err := Dial(opts)
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
	client.expireFreshness(keyOf(req))
	fake.set(nil, status.Error(codes.Unavailable, "server yo'q"))

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

	client.expireEntry(keyOf(req))
	fake.set(nil, status.Error(codes.Unavailable, "server yo'q"))

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

// ─────────────────────── Renew (lease yangilanishi) ───────────────────────

func denialResponse(code cc01v1.DenialCode) *cc01v1.AuthorizeTunnelResponse {
	return &cc01v1.AuthorizeTunnelResponse{
		Result: &cc01v1.AuthorizeTunnelResponse_Denial{
			Denial: &cc01v1.Denial{Code: code, Message: "rad etildi"},
		},
	}
}

func entryOf(t *testing.T, c *Client, req Request) (cacheEntry, bool) {
	t.Helper()
	return c.lookup(keyOf(req))
}

// Client Renewer'ni amalga oshiradi, AllowAll esa — yo'q (avtorizatsiya
// o'chirilgan rejimda yangilash bo'lmaydi).
func TestRenewer_ClientImplementsAllowAllDoesNot(t *testing.T) {
	var _ Renewer = (*Client)(nil)

	var authorizer Authorizer = &AllowAll{}
	if _, ok := authorizer.(Renewer); ok {
		t.Error("AllowAll Renewer'ni amalga oshirmasligi kerak")
	}
}

// Renew lease ichida ham keshni chetlab o'tadi — har chaqiruv AP'ga boradi.
func TestClient_RenewBypassesFreshCache(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	client := newTestClient(t, fake, time.Minute)

	req := Request{Token: "tok", Subdomain: "myapp"}
	if _, err := client.Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	for range 2 {
		if _, err := client.Renew(context.Background(), req); err != nil {
			t.Fatalf("Renew: %v", err)
		}
	}

	if got := fake.calls.Load(); got != 3 {
		t.Errorf("3 ta murojaat kutilgan (1 ochilish + 2 yangilash), %d bo'ldi", got)
	}
}

func TestClient_RenewSetsRenewalFlag(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	client := newTestClient(t, fake, time.Minute)

	req := Request{Token: "tok", Subdomain: "myapp", Protocol: "http"}

	if _, err := client.Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if last, _ := fake.last(); last.GetRenewal() {
		t.Error("ochilishda renewal=false bo'lishi kerak")
	}

	// Chaqiruvchi bayroqni qo'ymasa ham Renew uni o'rnatadi.
	if _, err := client.Renew(context.Background(), req); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	last, _ := fake.last()
	if !last.GetRenewal() {
		t.Error("Renew renewal=true yuborishi kerak")
	}
	if last.GetSubdomain() != "myapp" || last.GetToken() != "tok" ||
		last.GetProtocol() != cc01v1.Protocol_PROTOCOL_HTTP {
		t.Errorf("so'rov maydonlari noto'g'ri: %+v", last)
	}
}

// AP yo'q: Renew keshdagi (hali yaroqli) natijani QAYTARMAYDI — aks holda
// chaqiruvchi eski limitlarni "yangi" deb qabul qilardi.
func TestClient_RenewUnavailableReturnsErrUnavailableNotCachedGrant(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	client := newTestClient(t, fake, time.Hour)

	req := Request{Token: "tok", Subdomain: "myapp"}
	if _, err := client.Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	fake.set(nil, status.Error(codes.Unavailable, "server yo'q"))

	grant, err := client.Renew(context.Background(), req)
	if grant != nil {
		t.Errorf("grant nil bo'lishi kerak, olindi: %+v", grant)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ErrUnavailable kutilgan, olindi: %v", err)
	}
	var denial *Denial
	if errors.As(err, &denial) {
		t.Error("tarmoq xatosi Denial sifatida ko'rsatilmasligi kerak")
	}

	// Kesh yozuvi saqlanadi — yangi ochilishlar uchun fail-static ishlaydi.
	if _, ok := entryOf(t, client, req); !ok {
		t.Error("AP yo'qligida kesh yozuvi o'chirilmasligi kerak")
	}
}

// Renew timeout ham ErrUnavailable — rad javobi emas.
func TestClient_RenewTimeoutIsErrUnavailable(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60), delay: 300 * time.Millisecond}
	client := newTestClientWith(t, fake, Options{Grace: time.Hour, Timeout: 50 * time.Millisecond})

	_, err := client.Renew(context.Background(), Request{Token: "tok", Subdomain: "myapp"})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ErrUnavailable kutilgan, olindi: %v", err)
	}
}

func TestClient_RenewDenialForgetsCache(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	client := newTestClient(t, fake, time.Hour)

	req := Request{Token: "tok", Subdomain: "myapp"}
	if _, err := client.Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	fake.set(denialResponse(cc01v1.DenialCode_DENIAL_CODE_TOKEN_REVOKED), nil)

	grant, err := client.Renew(context.Background(), req)
	if grant != nil {
		t.Errorf("grant nil bo'lishi kerak, olindi: %+v", grant)
	}
	var denial *Denial
	if !errors.As(err, &denial) || denial.Code != "TOKEN_REVOKED" {
		t.Fatalf("TOKEN_REVOKED Denial kutilgan, olindi: %v", err)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Error("rad javobi ErrUnavailable bo'lmasligi kerak")
	}
	if _, ok := entryOf(t, client, req); ok {
		t.Error("rad javobidan keyin kesh yozuvi o'chirilishi kerak")
	}

	// Keyingi ochilish keshdan emas, AP'dan javob oladi — va AP yiqilgan
	// bo'lsa ham bekor qilingan token fail-static orqali qaytib kelmaydi.
	fake.set(nil, status.Error(codes.Unavailable, "server yo'q"))
	if _, err := client.Authorize(context.Background(), req); err == nil {
		t.Error("bekor qilingan token keshdan qayta tiklanmasligi kerak")
	}
}

// Renew natijasi keshga yoziladi: keyingi ochilish yangi limitlarni
// AP'ga bormasdan oladi.
func TestClient_RenewStoresForLaterOpens(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 24, 60)}
	client := newTestClient(t, fake, time.Hour)

	req := Request{Token: "tok", Subdomain: "myapp"}
	if _, err := client.Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	fake.set(grantResponse("myapp", 128, 60), nil)
	if _, err := client.Renew(context.Background(), req); err != nil {
		t.Fatalf("Renew: %v", err)
	}

	grant, err := client.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if grant.MaxConnsPerTunnel != 128 {
		t.Errorf("yangilangan limit kutilgan (128), olindi: %d", grant.MaxConnsPerTunnel)
	}
	if got := fake.calls.Load(); got != 2 {
		t.Errorf("2 ta murojaat kutilgan, %d bo'ldi", got)
	}
}

// Yangi edge + eski AP: AP renewal bayrog'ini bilmaydi va oddiy ochilish
// kabi javob beradi — grant baribir qo'llaniladi.
func TestClient_RenewAgainstAPIgnoringFlag(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 24, 60)}
	client := newTestClient(t, fake, time.Hour)

	req := Request{Token: "tok", Subdomain: "myapp"}
	if _, err := client.Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	fake.set(grantResponse("myapp", 128, 60), nil)
	grant, err := client.Renew(context.Background(), req)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if grant.MaxConnsPerTunnel != 128 || grant.Subdomain != "myapp" {
		t.Errorf("eski AP grant'i qo'llanilishi kerak, olindi: %+v", grant)
	}
}

// ─────────────────────── kesh yangiligi ───────────────────────

func TestClient_FreshnessCappedByMaxFresh(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	client := newTestClientWith(t, fake, Options{Grace: time.Hour, MaxFresh: 30 * time.Second})

	req := Request{Token: "tok", Subdomain: "myapp"}
	grant, err := client.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	entry, ok := entryOf(t, client, req)
	if !ok {
		t.Fatal("kesh yozuvi yo'q")
	}
	if got := entry.freshFor.Sub(grant.IssuedAt); got != 30*time.Second {
		t.Errorf("yangilik oynasi 30s kutilgan (MaxFresh < LeaseTTL), olindi: %s", got)
	}
	if got := entry.usableFor.Sub(grant.IssuedAt); got != time.Hour {
		t.Errorf("grace oynasi IssuedAt'dan 1h kutilgan, olindi: %s", got)
	}
}

// Yangilik edge'dagi yangilash oralig'iga teng: R = min(MaxFresh,
// LeaseTTL/2) — renewInterval bilan bir xil. MaxFresh LeaseTTL/2 dan katta
// bo'lsa, LeaseTTL/2 ustun: aks holda (CC01_ACCESS_RENEW=50s, lease 60 s)
// keshdan ochilgan tunnel o'zgarishni R + T = 33 s emas, 50 + 3 s da ko'rardi.
func TestClient_FreshnessCappedByRenewInterval(t *testing.T) {
	cases := []struct {
		name     string
		ttl      uint32
		maxFresh time.Duration
		want     time.Duration
	}{
		{"MaxFresh > LeaseTTL/2", 60, 50 * time.Second, 30 * time.Second},
		{"MaxFresh > LeaseTTL", 20, 30 * time.Second, 10 * time.Second},
		{"MaxFresh < LeaseTTL/2", 60, 10 * time.Second, 10 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAccessServer{response: grantResponse("myapp", 128, tc.ttl)}
			client := newTestClientWith(t, fake, Options{Grace: time.Hour, MaxFresh: tc.maxFresh})

			req := Request{Token: "tok", Subdomain: "myapp"}
			grant, err := client.Authorize(context.Background(), req)
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}

			entry, _ := entryOf(t, client, req)
			if got := entry.freshFor.Sub(grant.IssuedAt); got != tc.want {
				t.Errorf("yangilik oynasi %s (R) kutilgan, olindi: %s", tc.want, got)
			}
		})
	}
}

// MaxFresh = 0 — chegara yo'q: yangilik LeaseTTL bo'yicha (nol oyna emas).
func TestClient_MaxFreshZeroUsesLeaseTTL(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
	client := newTestClientWith(t, fake, Options{Grace: time.Hour})

	req := Request{Token: "tok", Subdomain: "myapp"}
	grant, err := client.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	entry, _ := entryOf(t, client, req)
	if got := entry.freshFor.Sub(grant.IssuedAt); got != time.Minute {
		t.Errorf("yangilik oynasi 60s (LeaseTTL) kutilgan, olindi: %s", got)
	}

	// Va kesh haqiqatan ishlaydi.
	if _, err := client.Authorize(context.Background(), req); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got := fake.calls.Load(); got != 1 {
		t.Errorf("MaxFresh=0 da kesh ishlashi kerak: %d murojaat", got)
	}
}

// Eski grant (IssuedAt oldinroq) yangiroq yozuvning ustiga yozilmaydi —
// tartibsiz qaytgan parallel yangilanishlar limitlarni orqaga qaytarmaydi.
func TestClient_StoreIsMonotonicByIssuedAt(t *testing.T) {
	client := newTestClient(t, &fakeAccessServer{}, time.Hour)

	key := keyOf(Request{Token: "tok", Subdomain: "myapp"})
	now := time.Now()

	newer := &Grant{MaxConnsPerTunnel: 128, LeaseTTL: time.Minute, IssuedAt: now}
	older := &Grant{MaxConnsPerTunnel: 24, LeaseTTL: time.Minute, IssuedAt: now.Add(-5 * time.Second)}

	client.store(key, newer)
	client.store(key, older)

	if grant, ok := client.cachedFresh(key); !ok || grant != newer {
		t.Fatalf("yangiroq grant saqlanishi kerak edi, olindi: %+v", grant)
	}

	// Teng yoki keyinroq IssuedAt — yoziladi.
	newest := &Grant{MaxConnsPerTunnel: 512, LeaseTTL: time.Minute, IssuedAt: now.Add(time.Second)}
	client.store(key, newest)
	if grant, _ := client.cachedFresh(key); grant != newest {
		t.Errorf("eng yangi grant yozilishi kerak edi, olindi: %+v", grant)
	}
}

// IssuedAt — RPC boshlangan vaqt (javob kelgan vaqt emas) va keshdan
// qaytganda o'zgarmaydi.
func TestClient_IssuedAtIsCallStartAndPreservedOnCacheHit(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60), delay: 100 * time.Millisecond}
	client := newTestClient(t, fake, time.Hour)

	req := Request{Token: "tok", Subdomain: "myapp"}

	before := time.Now()
	grant, err := client.Authorize(context.Background(), req)
	after := time.Now()
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	_, handledAt := fake.last()
	if grant.IssuedAt.Before(before) || grant.IssuedAt.After(handledAt) {
		t.Errorf("IssuedAt RPC boshlanishida bo'lishi kerak: before=%s issued=%s handled=%s",
			before, grant.IssuedAt, handledAt)
	}
	// Server 100 ms kutdi — IssuedAt javob vaqtidan ancha oldin.
	if after.Sub(grant.IssuedAt) < 100*time.Millisecond {
		t.Errorf("IssuedAt javob vaqtiga yaqin: %s", after.Sub(grant.IssuedAt))
	}

	time.Sleep(10 * time.Millisecond)
	cached, err := client.Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorize (kesh): %v", err)
	}
	if fake.calls.Load() != 1 {
		t.Fatalf("ikkinchi so'rov keshdan kelishi kerak edi")
	}
	if !cached.IssuedAt.Equal(grant.IssuedAt) {
		t.Errorf("keshdan qaytganda IssuedAt saqlanishi kerak: %s != %s", cached.IssuedAt, grant.IssuedAt)
	}
}

// AllowAll natijasida IssuedAt nol — u faqat Client tomonidan qo'yiladi.
func TestAllowAll_IssuedAtIsZero(t *testing.T) {
	grant, _ := (&AllowAll{}).Authorize(context.Background(), Request{Subdomain: "x"})
	if !grant.IssuedAt.IsZero() {
		t.Errorf("AllowAll uchun IssuedAt nol bo'lishi kerak: %s", grant.IssuedAt)
	}
}

// ─────────────────── rad javobi va kesh tozaligi ───────────────────

// Klient bo'sh subdomain bilan ochadi (AP hisobdagi nomni tanlaydi):
// kesh kaliti "h||", yangilash esa BERILGAN nom bilan ("h|myapp|") ketadi.
// Yangilashdagi rad javobi "h||" yozuvini ham o'chirishi kerak — aks holda
// klient bo'sh subdomain bilan qayta ulanganda bekor qilingan token keshdan
// (yangi oynada yoki AP yiqilsa grace davomida) tunnel olardi.
func TestClient_RenewDenialPurgesOriginalOpenKey(t *testing.T) {
	cases := []struct {
		code      cc01v1.DenialCode
		otherKept bool // boshqa nom uchun yozuv saqlanadimi
	}{
		{cc01v1.DenialCode_DENIAL_CODE_TOKEN_REVOKED, false},
		{cc01v1.DenialCode_DENIAL_CODE_PLAN_SUSPENDED, false},
		{cc01v1.DenialCode_DENIAL_CODE_SUBDOMAIN_NOT_OWNED, true},
	}
	for _, tc := range cases {
		t.Run(tc.code.String(), func(t *testing.T) {
			fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60)}
			client := newTestClient(t, fake, time.Hour)

			open := Request{Token: "tok"} // subdomain bo'sh
			if _, err := client.Authorize(context.Background(), open); err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			fake.set(grantResponse("other", 128, 60), nil)
			other := Request{Token: "tok", Subdomain: "other"}
			if _, err := client.Authorize(context.Background(), other); err != nil {
				t.Fatalf("Authorize (other): %v", err)
			}

			// renew.go aynan shunday yuboradi: berilgan nom bilan.
			fake.set(denialResponse(tc.code), nil)
			if _, err := client.Renew(context.Background(), Request{Token: "tok", Subdomain: "myapp"}); err == nil {
				t.Fatal("rad javobi kutilgan")
			}

			if _, ok := entryOf(t, client, open); ok {
				t.Error("asl ochilish kaliti (bo'sh subdomain) keshda qoldi")
			}
			if _, ok := entryOf(t, client, other); ok != tc.otherKept {
				t.Errorf("boshqa nom yozuvi: saqlangan=%v, kutilgan=%v", ok, tc.otherKept)
			}

			// AP yiqildi: bekor qilingan token fail-static orqali ham
			// qaytib kelmaydi.
			fake.set(nil, status.Error(codes.Unavailable, "server yo'q"))
			calls := fake.calls.Load()
			if _, err := client.Authorize(context.Background(), open); err == nil {
				t.Error("rad etilgan token bo'sh subdomain bilan keshdan tunnel oldi")
			}
			if fake.calls.Load() == calls {
				t.Error("ochilish keshdan javob oldi, AP'ga bormadi")
			}
		})
	}
}

// Yo'ldagi eski grant rad javobidan keyin keshni qayta tiriltirmaydi:
// A (ochilish) s0 da boshlanadi, token bekor qilinadi, B (yangilash)
// keyinroq boshlanib rad oladi, so'ng A'ning (bekor qilishdan oldingi)
// javobi keladi. A'ning grant'i keshga yozilmasligi kerak.
func TestClient_InFlightGrantDoesNotResurrectAfterDenial(t *testing.T) {
	client := newTestClient(t, &fakeAccessServer{}, time.Hour)

	open := Request{Token: "tok"}
	s0 := time.Now()
	// B rad javobini oldi (RPC s0 dan keyin boshlangan).
	client.forgetDenied(keyOf(Request{Token: "tok", Subdomain: "myapp"}), "TOKEN_REVOKED", s0.Add(200*time.Millisecond))
	// A'ning javobi endi keldi.
	client.store(keyOf(open), &Grant{Subdomain: "myapp", LeaseTTL: time.Minute, IssuedAt: s0})

	if _, ok := client.cachedUsable(keyOf(open)); ok {
		t.Fatal("rad javobidan oldin boshlangan grant keshga yozildi")
	}

	// Rad javobidan KEYIN boshlangan grant (masalan, token qayta
	// faollashtirilgan) odatdagidek yoziladi.
	newer := &Grant{Subdomain: "myapp", LeaseTTL: time.Minute, IssuedAt: s0.Add(time.Second)}
	client.store(keyOf(open), newer)
	if g, ok := client.cachedFresh(keyOf(open)); !ok || g != newer {
		t.Errorf("izdan keyingi grant yozilishi kerak edi, olindi: %+v", g)
	}
}

// Nom darajasidagi rad javobi izi faqat shu nomni yopadi: berilgan nomi
// shu bo'lgan eski grant yozilmaydi, boshqa nom esa yoziladi.
func TestClient_SubdomainDenialTombstoneIsScoped(t *testing.T) {
	client := newTestClient(t, &fakeAccessServer{}, time.Hour)

	s0 := time.Now()
	client.forgetDenied(keyOf(Request{Token: "tok", Subdomain: "myapp"}), "SUBDOMAIN_NOT_OWNED", s0)

	empty := keyOf(Request{Token: "tok"})
	client.store(empty, &Grant{Subdomain: "myapp", LeaseTTL: time.Minute, IssuedAt: s0.Add(-time.Second)})
	if _, ok := client.cachedUsable(empty); ok {
		t.Error("rad etilgan nomni bergan eski grant keshga yozildi")
	}

	other := keyOf(Request{Token: "tok", Subdomain: "other"})
	client.store(other, &Grant{Subdomain: "other", LeaseTTL: time.Minute, IssuedAt: s0.Add(-time.Second)})
	if _, ok := client.cachedUsable(other); !ok {
		t.Error("boshqa nom uchun grant yozilishi kerak edi")
	}
}

// Haqiqiy RPC'lar bilan poyga: sekin ochilish javobi rad javobidan keyin
// keladi.
func TestClient_SlowOpenAfterRenewDenialIsNotCached(t *testing.T) {
	fake := &fakeAccessServer{response: grantResponse("myapp", 128, 60), delay: 300 * time.Millisecond}
	client := newTestClient(t, fake, time.Hour)

	open := Request{Token: "tok"}
	done := make(chan error, 1)
	go func() {
		_, err := client.Authorize(context.Background(), open)
		done <- err
	}()

	// A server ichida — javob hali qaytmagan.
	for fake.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	fake.mu.Lock()
	fake.delay = 0
	fake.response = denialResponse(cc01v1.DenialCode_DENIAL_CODE_TOKEN_REVOKED)
	fake.mu.Unlock()

	if _, err := client.Renew(context.Background(), Request{Token: "tok", Subdomain: "myapp"}); err == nil {
		t.Fatal("rad javobi kutilgan")
	}
	if err := <-done; err != nil {
		t.Fatalf("Authorize: %v", err)
	}

	if _, ok := entryOf(t, client, open); ok {
		t.Error("rad javobidan keyin kelgan eski grant keshni qayta tiriltirdi")
	}
}

// Iz va grace'i tugagan yozuvlar xotirada abadiy qolmaydi.
func TestClient_SweepDropsExpiredTombstonesAndEntries(t *testing.T) {
	client := newTestClientWith(t, &fakeAccessServer{}, Options{Grace: time.Hour, Timeout: time.Second})

	old := time.Now().Add(-time.Hour)
	client.forgetDenied(keyOf(Request{Token: "a"}), "TOKEN_INVALID", old)
	client.store(keyOf(Request{Token: "b"}), &Grant{LeaseTTL: time.Minute, IssuedAt: old.Add(-time.Minute)})

	client.mu.Lock()
	client.lastSweep = time.Time{}
	client.sweepLocked(time.Now())
	n := len(client.cache)
	client.mu.Unlock()

	if n != 0 {
		t.Errorf("eskirgan yozuvlar tozalanmadi: %d token qoldi", n)
	}
}
