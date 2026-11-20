package access

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (f *fakeAccessServer) ReportUsage(
	_ context.Context,
	req *cc01v1.ReportUsageRequest,
) (*cc01v1.ReportUsageResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usageReqs = append(f.usageReqs, req)
	if f.usageErr != nil {
		return nil, f.usageErr
	}
	n := uint32(len(req.GetWindows()))
	if f.usageAccepted != nil {
		n = f.usageAccepted(len(req.GetWindows()))
	}
	return &cc01v1.ReportUsageResponse{Accepted: n}, nil
}

func (f *fakeAccessServer) usageRequests() []*cc01v1.ReportUsageRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*cc01v1.ReportUsageRequest(nil), f.usageReqs...)
}

var testWindows = []UsageWindow{
	{
		TenantID: "acme", TunnelID: "web.cc01.uz:80/0123456789abcdef",
		WindowStart: 1_700_000_000, WindowEnd: 1_700_000_060,
		BytesIn: 1 << 40, BytesOut: 12345, Connections: 7, Rejected: 2,
	},
	{
		TenantID: "acme", TunnelID: "db.cc01.uz:24801/fedcba9876543210",
		WindowStart: 1_700_000_013, WindowEnd: 1_700_000_060,
	},
}

// Client UsageReporter'ni amalga oshiradi, AllowAll esa — yo'q
// (avtorizatsiya o'chirilgan rejimda hisobot yuborilmaydi).
func TestUsageReporter_ClientImplementsAllowAllDoesNot(t *testing.T) {
	var _ UsageReporter = (*Client)(nil)

	var authorizer Authorizer = &AllowAll{}
	if _, ok := authorizer.(UsageReporter); ok {
		t.Error("AllowAll UsageReporter'ni amalga oshirmasligi kerak")
	}
}

// Har maydon proto'ga aynan o'tadi, accepted qaytariladi.
func TestClient_ReportUsageSendsWindows(t *testing.T) {
	fake := &fakeAccessServer{}
	client := newTestClient(t, fake, time.Minute)

	accepted, err := client.ReportUsage(context.Background(), testWindows)
	if err != nil {
		t.Fatalf("kutilmagan xato: %v", err)
	}
	if accepted != 2 {
		t.Fatalf("accepted=%d, 2 kutilgan", accepted)
	}

	reqs := fake.usageRequests()
	if len(reqs) != 1 {
		t.Fatalf("%d ta RPC, 1 kutilgan", len(reqs))
	}
	got := reqs[0].GetWindows()
	if len(got) != len(testWindows) {
		t.Fatalf("%d oyna yuborildi", len(got))
	}
	for i, w := range testWindows {
		g := got[i]
		back := UsageWindow{
			TenantID: g.GetTenantId(), TunnelID: g.GetTunnelId(),
			WindowStart: g.GetWindowStart(), WindowEnd: g.GetWindowEnd(),
			BytesIn: g.GetBytesIn(), BytesOut: g.GetBytesOut(),
			Connections: g.GetConnections(), Rejected: g.GetRejected(),
		}
		if back != w {
			t.Errorf("oyna %d: %+v yuborildi, %+v kutilgan", i, back, w)
		}
	}
}

// Bo'sh ro'yxat AP'ga bormaydi.
func TestClient_ReportUsageEmptyIsNoop(t *testing.T) {
	fake := &fakeAccessServer{}
	client := newTestClient(t, fake, time.Minute)

	if n, err := client.ReportUsage(context.Background(), nil); n != 0 || err != nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(fake.usageRequests()) != 0 {
		t.Fatal("bo'sh ro'yxat uchun RPC ketmasligi kerak")
	}
}

// AP qisman qabul qilsa — o'sha son; len dan ko'p desa — len ga qisqaradi.
func TestClient_ReportUsageAcceptedCount(t *testing.T) {
	fake := &fakeAccessServer{usageAccepted: func(int) uint32 { return 1 }}
	client := newTestClient(t, fake, time.Minute)

	if n, err := client.ReportUsage(context.Background(), testWindows); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v, 1 kutilgan", n, err)
	}

	fake.mu.Lock()
	fake.usageAccepted = func(int) uint32 { return 99 }
	fake.mu.Unlock()
	if n, err := client.ReportUsage(context.Background(), testWindows); err != nil || n != 2 {
		t.Fatalf("n=%d err=%v, 2 kutilgan", n, err)
	}
}

// Har qanday RPC xatosi (Unavailable, Unimplemented — eski AP, taymaut)
// ErrUnavailable: 0 qabul qilingan, chaqiruvchi oynalarni saqlaydi.
func TestClient_ReportUsageErrorsAreUnavailable(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.Unimplemented, codes.Internal} {
		fake := &fakeAccessServer{usageErr: status.Error(code, "yo'q")}
		client := newTestClient(t, fake, time.Minute)

		n, err := client.ReportUsage(context.Background(), testWindows)
		if n != 0 || !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: n=%d err=%v, ErrUnavailable kutilgan", code, n, err)
		}
	}

	// AP butunlay yo'q (portda hech kim tinglamaydi) — taymaut ichida xato.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	client, err := Dial(Options{Address: addr, Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	started := time.Now()
	n, err := client.ReportUsage(context.Background(), testWindows)
	if n != 0 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if d := time.Since(started); d > 2*time.Second {
		t.Fatalf("xato %s dan keyin qaytdi", d)
	}
}

// mTLS kanali orqali ham (prod yo'li).
func TestMTLS_ReportUsage(t *testing.T) {
	t.Parallel()
	env := newMTLSEnv(t)
	fake := &fakeAccessServer{}
	srv := startTLSAccessServer(t, fake, env.apCA.issueServer(t), env.edgeCA)
	client := dialTLS(t, srv.addr, env.clientTLS(t, "127.0.0.1"))

	n, err := client.ReportUsage(context.Background(), testWindows)
	if err != nil || n != len(testWindows) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if cns := srv.seenCNs(); len(cns) != 1 || cns[0] != "edge-test" {
		t.Fatalf("server ko'rgan CN'lar: %v", cns)
	}
}
