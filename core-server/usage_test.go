package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/freco-dev/cc01/core-server/access"
	"github.com/freco-dev/cc01/core-server/config"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// usageAP — fakeAP + UsageReporter: qabul qilingan oynalarni yozib boradi.
type usageAP struct {
	*fakeAP

	mu      sync.Mutex
	windows []access.UsageWindow
}

func (u *usageAP) ReportUsage(_ context.Context, windows []access.UsageWindow) (int, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.windows = append(u.windows, windows...)
	return len(windows), nil
}

func (u *usageAP) windowsOf(id string) []access.UsageWindow {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []access.UsageWindow
	for _, w := range u.windows {
		if w.TunnelID == id {
			out = append(out, w)
		}
	}
	return out
}

var tunnelIDPattern = regexp.MustCompile(`^[a-z0-9.-]+:\d+/[0-9a-f]{16}$`)

// Tunnel orqali haqiqiy trafik: yopilgan tunnelning yakuniy oynasi AP'ga
// yetib boradi va oynalar yig'indisi aynan o'tgan baytlar, qabul
// qilingan va max_conns tufayli rad etilgan ulanishlarga teng.
func TestServe_UsageFinalWindowReported(t *testing.T) {
	grant := freeGrant
	grant.TenantID = "acme"
	grant.MaxConnsPerTunnel = 1
	ap := &usageAP{fakeAP: newFakeAP(grant)}
	h := newServeHarness(t, ap, 0)

	// Sozlamadagi chegara (≥ 5 s) faqat Load'da; sinov uchun 1 s oyna.
	h.j.config.UsageInterval = time.Second
	h.j.initUsage()
	if h.j.usage == nil {
		t.Fatal("UsageReporter bilan hisobot yoqilishi kerak edi")
	}
	h.j.usage.Start()
	t.Cleanup(func() { h.j.usage.Stop(time.Second) })

	control, opened := h.open(t, cc01v1.Protocol_PROTOCOL_TCP, "dbx")
	if opened.GetErrorCode() != "" {
		t.Fatalf("tunnel ochilmadi: %s", opened.GetErrorMessage())
	}
	id := opened.GetTunnelId()
	if !tunnelIDPattern.MatchString(id) || len(id) > maxTunnelIDLen {
		t.Fatalf("tunnel ID: %q", id)
	}
	eventually(t, 5*time.Second, "[tunnel-opened] shu ID bilan", func() bool {
		return strings.Contains(h.logs.String(), "[tunnel-opened] "+id+" tenant=acme")
	})

	// 1-ulanish: ko'prik, ikki tomonga trafik.
	public, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", opened.GetPublicPort()))
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	received := readFrame(t, control).GetConnectionReceived()
	if received == nil || received.GetRateLimited() {
		t.Fatalf("ConnectionReceived kutilgan edi: %v", received)
	}
	private, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", opened.GetPrivatePort()))
	if err != nil {
		t.Fatal(err)
	}
	defer private.Close()
	portBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBuf, uint16(received.GetClientPort()))
	if _, err := private.Write(portBuf); err != nil {
		t.Fatal(err)
	}

	const in, out = 70_001, 123_457
	pipe(t, public, private, in)
	pipe(t, private, public, out)

	// 2-ulanish navbatda (juftlanmagan) qoladi va max_conns=1 ni
	// to'ldiradi; 3-si rad etiladi. (Limit juftlanmagan ulanishlarga
	// qo'llanadi — tunnel.acceptPublic.)
	pending, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", opened.GetPublicPort()))
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	if readFrame(t, control).GetConnectionReceived().GetRateLimited() {
		t.Fatal("2-ulanish qabul qilinishi kerak edi")
	}
	rejected, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", opened.GetPublicPort()))
	if err != nil {
		t.Fatal(err)
	}
	defer rejected.Close()
	if !readFrame(t, control).GetConnectionReceived().GetRateLimited() {
		t.Fatal("3-ulanish limitga tushishi kerak edi")
	}

	// Klient ketdi — tunnel yopiladi, yakuniy oyna kesiladi.
	_ = control.Close()
	h.waitServeDone(t, 5*time.Second)
	closedAt := time.Now().Unix()

	var windows []access.UsageWindow
	eventually(t, 5*time.Second, "yakuniy oyna AP'ga yetdi", func() bool {
		windows = ap.windowsOf(id)
		return len(windows) > 0 && windows[len(windows)-1].WindowEnd >= closedAt
	})

	var sumIn, sumOut uint64
	var conns, rej uint32
	for i, w := range windows {
		if w.TenantID != "acme" {
			t.Errorf("tenant: %q", w.TenantID)
		}
		if w.WindowEnd <= w.WindowStart {
			t.Errorf("bo'sh oyna: %+v", w)
		}
		if i > 0 && w.WindowStart != windows[i-1].WindowEnd {
			t.Errorf("uzilish yoki ustma-ust: %+v → %+v", windows[i-1], w)
		}
		sumIn, sumOut = sumIn+w.BytesIn, sumOut+w.BytesOut
		conns, rej = conns+w.Connections, rej+w.Rejected
	}
	if sumIn != in || sumOut != out || conns != 2 || rej != 1 {
		t.Fatalf("yig'indi in=%d out=%d conns=%d rejected=%d, kutilgan %d/%d/2/1\n%+v",
			sumIn, sumOut, conns, rej, in, out, windows)
	}

	// Yopilgan tunnel uchun boshqa oyna kelmaydi.
	time.Sleep(1500 * time.Millisecond)
	if n := len(ap.windowsOf(id)); n != len(windows) {
		t.Fatalf("yopilgandan keyin oyna qo'shildi: %d → %d", len(windows), n)
	}
}

// pipe src'ga n bayt yozadi va dst'dan aynan n bayt o'qiydi.
func pipe(t *testing.T, src, dst net.Conn, n int) {
	t.Helper()
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := src.Write(payload)
		errc <- err
	}()
	_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer dst.SetReadDeadline(time.Time{})
	if _, err := io.ReadFull(dst, make([]byte, n)); err != nil {
		t.Fatalf("%d bayt o'qilmadi: %v", n, err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

// Xuddi shu nom bilan qayta ochilgan tunnel yangi ID oladi: aks holda
// uning oynalari AP'da avvalgisiniki bilan (tunnel_id, window_start)
// bo'yicha to'qnashib, dublikat sifatida tashlanardi.
func TestServe_TunnelIDUniqueAcrossReopen(t *testing.T) {
	h := newServeHarness(t, newFakeAP(freeGrant), 0)

	seen := map[string]bool{}
	for range 3 {
		control, opened := h.open(t, cc01v1.Protocol_PROTOCOL_HTTP, "demo")
		if opened.GetErrorCode() != "" {
			t.Fatalf("tunnel ochilmadi: %s", opened.GetErrorMessage())
		}
		id := opened.GetTunnelId()
		if !strings.HasPrefix(id, "demo.cc01.test:80/") || !tunnelIDPattern.MatchString(id) {
			t.Fatalf("tunnel ID: %q", id)
		}
		if seen[id] {
			t.Fatalf("ID takrorlandi: %q", id)
		}
		seen[id] = true

		_ = control.Close()
		h.waitServeDone(t, 5*time.Second)
		if !strings.Contains(h.logs.String(), "[tunnel-closed] "+id) {
			t.Fatalf("[tunnel-closed] shu ID bilan yozilmadi:\n%s", h.logs.String())
		}
	}
}

func TestNewTunnelID_UniqueAndBounded(t *testing.T) {
	long := strings.Repeat("a", 38) + "." + strings.Repeat("b", 200)
	seen := map[string]bool{}
	for range 1000 {
		for _, host := range []string{"x.cc01.uz", long} {
			id := newTunnelID(host, 24801)
			if len(id) > maxTunnelIDLen {
				t.Fatalf("ID %d belgi: %q", len(id), id)
			}
			if seen[id] {
				t.Fatalf("ID takrorlandi: %q", id)
			}
			seen[id] = true
		}
	}
	if id := newTunnelID("x.cc01.uz", 80); !regexp.MustCompile(`^x\.cc01\.uz:80/[0-9a-f]{16}$`).MatchString(id) {
		t.Fatalf("format: %q", id)
	}
}

// Hisobot faqat UsageReporter bilan va oraliq > 0 da yoqiladi: AllowAll
// (CC01_AUTH_MODE=disabled) hech qachon hisobot yubormaydi.
func TestInitUsage_EnabledOnlyWithReporter(t *testing.T) {
	cases := []struct {
		name     string
		auth     access.Authorizer
		mode     config.AuthMode
		interval time.Duration
		want     bool
	}{
		{"AllowAll", &access.AllowAll{}, config.AuthDisabled, time.Minute, false},
		{"reporter, interval 0", &usageAP{fakeAP: newFakeAP(freeGrant)}, config.AuthRequired, 0, false},
		{"authorizer without reporter", newFakeAP(freeGrant), config.AuthRequired, time.Minute, false},
		{"reporter", &usageAP{fakeAP: newFakeAP(freeGrant)}, config.AuthRequired, time.Minute, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := &CC01Server{
				config:     config.Config{AuthMode: tc.mode, UsageInterval: tc.interval},
				authorizer: tc.auth,
				logOut:     io.Discard,
			}
			j.initUsage()
			if got := j.usage != nil; got != tc.want {
				t.Fatalf("hisobot yoqilgan=%v, %v kutilgan", got, tc.want)
			}
		})
	}
}
