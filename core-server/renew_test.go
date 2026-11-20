package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/freco-dev/cc01/core-server/access"
	"github.com/freco-dev/cc01/core-server/config"
	"github.com/freco-dev/cc01/core-server/events"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// ─────────────────────────── soxta AP ───────────────────────────

var (
	freeGrant = access.Grant{
		UserID: 7, TenantID: "t1", Plan: "free", Subdomain: "myapp",
		MaxTunnels: 1, MaxConnsPerTunnel: 24, LeaseTTL: time.Minute,
	}
	proGrant = access.Grant{
		UserID: 7, TenantID: "t1", Plan: "pro", Subdomain: "myapp",
		MaxTunnels: 10, MaxConnsPerTunnel: 128, LeaseTTL: time.Minute,
	}
)

const testToken = "cc01_live_abc_SIR-TOKEN"

type renewCall struct {
	at  time.Time
	req access.Request
}

// fakeAP — Authorizer + Renewer. Renew AP holatini chaqiruv BOSHIDA
// o'qiydi (haqiqiy AP kabi: qaror RPC boshlangan paytdagi ma'lumotga
// asoslanadi), keyin rpc qadar "tarmoqda" turadi.
type fakeAP struct {
	mu      sync.Mutex
	state   access.Grant
	err     error // nil bo'lmasa Renew uni qaytaradi
	rpc     time.Duration
	calls   []renewCall
	onStart func(n int) // n-chaqiruv boshlandi (holat allaqachon o'qilgan)
}

func newFakeAP(state access.Grant) *fakeAP { return &fakeAP{state: state} }

func (f *fakeAP) Authorize(_ context.Context, req access.Request) (*access.Grant, error) {
	f.mu.Lock()
	g := f.state
	f.mu.Unlock()
	g.IssuedAt = time.Now()
	if req.Subdomain != "" {
		g.Subdomain = req.Subdomain
	}
	return &g, nil
}

func (f *fakeAP) Renew(ctx context.Context, req access.Request) (*access.Grant, error) {
	started := time.Now()

	f.mu.Lock()
	snapshot, err, rpc, hook := f.state, f.err, f.rpc, f.onStart
	n := len(f.calls)
	f.calls = append(f.calls, renewCall{at: started, req: req})
	f.mu.Unlock()

	if hook != nil {
		hook(n)
	}
	if rpc > 0 {
		select {
		case <-time.After(rpc):
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", access.ErrUnavailable, ctx.Err())
		}
	}
	if err != nil {
		return nil, err
	}
	snapshot.IssuedAt = started
	snapshot.Subdomain = req.Subdomain
	return &snapshot, nil
}

func (f *fakeAP) Close() error { return nil }

func (f *fakeAP) setState(g access.Grant) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = g
}

func (f *fakeAP) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeAP) callLog() []renewCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]renewCall(nil), f.calls...)
}

// fakeSink — tunnel limitlari; har o'rnatish vaqti bilan yoziladi.
type fakeSink struct {
	mu      sync.Mutex
	n       int
	applied []sinkSet
}

type sinkSet struct {
	at time.Time
	n  int
}

func (s *fakeSink) SetMaxConns(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n = n
	s.applied = append(s.applied, sinkSet{at: time.Now(), n: n})
}

func (s *fakeSink) MaxConns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// firstApplied — n qiymati birinchi marta o'rnatilgan vaqt.
func (s *fakeSink) firstApplied(n int) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.applied {
		if a.n == n {
			return a.at, true
		}
	}
	return time.Time{}, false
}

func (s *fakeSink) sets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.applied)
}

// syncBuffer — log yozuvchisi (bir nechta goroutine yozadi).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type notifyRecorder struct {
	mu    sync.Mutex
	codes []string
	msgs  []string
}

func (r *notifyRecorder) notify(code, msg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.codes = append(r.codes, code)
	r.msgs = append(r.msgs, msg)
	return nil
}

func (r *notifyRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.codes)
}

// ─────────────────────── supervisor harness ───────────────────────

const (
	testR   = 30 * time.Second // config.DefaultAccessRenew
	testRPC = 3 * time.Second  // config.DefaultAccessTimeout
)

type supervised struct {
	sink       *fakeSink
	notes      *notifyRecorder
	logs       *syncBuffer
	clientGone chan struct{}
	done       chan *access.Denial

	finished bool
	result   *access.Denial
}

// returned — supervisor qaytdimi (bloklamaydi; natija saqlanadi).
func (s *supervised) returned() bool {
	if s.finished {
		return true
	}
	select {
	case d := <-s.done:
		s.finished, s.result = true, d
		return true
	default:
		return false
	}
}

// stop klientni "ketkazadi" va supervisor qaytishini kutadi.
func (s *supervised) stop(t *testing.T) *access.Denial {
	t.Helper()
	close(s.clientGone)
	if !s.finished {
		s.finished, s.result = true, <-s.done
	}
	return s.result
}

func newSupervisorServer(auth access.Authorizer, renew time.Duration, deny config.RenewDenyMode, logs io.Writer) *CC01Server {
	return &CC01Server{
		config: config.Config{
			MaxConsPerTunnel: 24,
			AccessRenew:      renew,
			AccessRenewDeny:  deny,
		},
		authorizer: auth,
		logOut:     logs,
	}
}

// startSupervisor superviseTunnel ni alohida goroutine'da ishga tushiradi
// (synctest pufagi ichida chaqiriladi).
func startSupervisor(j *CC01Server, req access.Request, g *access.Grant) *supervised {
	s := &supervised{
		sink:       &fakeSink{n: j.effectiveMaxConns(g)},
		notes:      &notifyRecorder{},
		clientGone: make(chan struct{}),
		done:       make(chan *access.Denial, 1),
	}
	if b, ok := j.logOut.(*syncBuffer); ok {
		s.logs = b
	}
	go func() {
		s.done <- j.superviseTunnel(context.Background(), s.sink, s.notes.notify,
			req, g, "myapp.cc01.test:80", s.clientGone)
	}()
	return s
}

func openRequest(subdomain string) access.Request {
	return access.Request{
		Token:     testToken,
		Protocol:  "http",
		Subdomain: subdomain,
	}
}

// ───────────────────── 60 s kafolati (synctest) ─────────────────────

// TestSupervise_PropagationBudget — DEV_SPEC §8 qabul mezoni: tarif
// o'zgarishi ochiq tunnelga ≤ R + T (30 + 3 = 33 s) ichida, har holda
// 60 s dan tez yetib boradi. Virtual vaqtda, jitter'ning har xil
// qiymatlari uchun ko'p marta.
func TestSupervise_PropagationBudget(t *testing.T) {
	type setup struct {
		req      access.Request
		grant    *access.Grant
		changeAt time.Time // o'zgarish AP'da qachon kuchga kirgan
	}

	cases := []struct {
		name string
		// prepare AP va tunnel holatini tayyorlaydi. changeAt nol qolsa —
		// o'zgarishni ap.onStart ilgagi belgilaydi.
		prepare func(ap *fakeAP, now time.Time, change func()) setup
	}{
		{
			// (a) Eng yomon faza: o'zgarish yangilash BOSHLANGANIDAN
			// keyin tushadi — u eski holatni qaytaradi, o'zgarishni
			// faqat keyingisi ko'radi.
			name: "worst phase: change just after a renewal started",
			prepare: func(ap *fakeAP, now time.Time, change func()) setup {
				g := freeGrant
				g.IssuedAt = now
				ap.onStart = func(n int) {
					if n == 1 {
						change()
					}
				}
				return setup{req: openRequest("myapp"), grant: &g}
			},
		},
		{
			// (b) Tunnel keshdagi natija bilan ochilgan: IssuedAt = now − R
			// (MaxFresh = R da eng katta yosh). O'zgarish o'sha natijadan
			// darhol keyin tushgan — birinchi yangilash kechikmasligi shart.
			name: "opened from a cache entry R old",
			prepare: func(ap *fakeAP, now time.Time, _ func()) setup {
				g := freeGrant
				g.IssuedAt = now.Add(-testR)
				ap.setState(proGrant)
				return setup{req: openRequest("myapp"), grant: &g, changeAt: g.IssuedAt.Add(time.Nanosecond)}
			},
		},
		{
			// (c) Bo'sh subdomain bilan ochilgan (kesh kaliti "|"),
			// natija R ga yaqin yoshda.
			name: "empty-subdomain open with near-R-old grant",
			prepare: func(ap *fakeAP, now time.Time, _ func()) setup {
				g := freeGrant
				g.IssuedAt = now.Add(-testR + time.Second)
				ap.setState(proGrant)
				return setup{req: openRequest(""), grant: &g, changeAt: g.IssuedAt.Add(time.Nanosecond)}
			},
		},
		{
			// (d) O'zgarish yangilash "tarmoqda" bo'lgan paytda tushadi.
			name: "renewal in flight when the change commits",
			prepare: func(ap *fakeAP, now time.Time, change func()) setup {
				g := freeGrant
				g.IssuedAt = now
				ap.onStart = func(n int) {
					if n == 1 {
						go func() {
							time.Sleep(testRPC / 2)
							change()
						}()
					}
				}
				return setup{req: openRequest("myapp"), grant: &g}
			},
		},
	}

	const runs = 40 // jitter U[0.8,1] ning turli qiymatlari
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var worst time.Duration
			for range runs {
				synctest.Test(t, func(t *testing.T) {
					ap := newFakeAP(freeGrant)
					ap.rpc = testRPC

					var mu sync.Mutex
					var changeAt time.Time
					change := func() {
						ap.setState(proGrant)
						mu.Lock()
						changeAt = time.Now()
						mu.Unlock()
					}

					st := tc.prepare(ap, time.Now(), change)
					if !st.changeAt.IsZero() {
						changeAt = st.changeAt
					}

					j := newSupervisorServer(ap, testR, config.RenewDenyClose, io.Discard)
					s := startSupervisor(j, st.req, st.grant)

					// Yetarlicha virtual vaqt: chegara buzilsa ham natija ko'rinadi.
					time.Sleep(5 * time.Minute)
					synctest.Wait()

					applied, ok := s.sink.firstApplied(proGrant.MaxConnsPerTunnel)
					if !ok {
						t.Fatal("pro limitlari umuman qo'llanmadi")
					}
					mu.Lock()
					lag := applied.Sub(changeAt)
					mu.Unlock()

					if lag > testR+testRPC {
						t.Errorf("o'zgarish %s da qo'llandi, ≤ %s kutilgan", lag, testR+testRPC)
					}
					if lag >= time.Minute {
						t.Errorf("60 s kafolati buzildi: %s", lag)
					}
					worst = max(worst, lag)

					for _, c := range ap.callLog() {
						if c.req.Subdomain != "myapp" || !c.req.Renewal || c.req.Token != testToken {
							t.Fatalf("yangilash so'rovi noto'g'ri: %+v", c.req)
						}
					}
					if s.returned() {
						t.Fatal("supervisor kutilmaganda qaytdi")
					}
					if d := s.stop(t); d != nil {
						t.Fatalf("rad javobi kutilmagan edi: %v", d)
					}
				})
			}
			t.Logf("eng yomon kechikish: %s (chegara %s)", worst, testR+testRPC)
		})
	}
}

// AP yo'q bo'lsa ochiq tunnel oxirgi limitlar bilan muddatsiz ishlaydi,
// qayta urinishlar esa ≤ 10 s oralig'ida.
func TestSupervise_UnavailableKeepsLimitsForever(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ap := newFakeAP(freeGrant)
		ap.setErr(fmt.Errorf("%w: connection refused", access.ErrUnavailable))

		g := freeGrant
		g.IssuedAt = time.Now()
		logs := &syncBuffer{}
		j := newSupervisorServer(ap, testR, config.RenewDenyClose, logs)
		s := startSupervisor(j, openRequest("myapp"), &g)

		time.Sleep(2 * time.Hour)
		synctest.Wait()

		if s.returned() {
			t.Fatal("AP yo'qligi tunnelni yopdi")
		}
		if s.sink.sets() != 0 || s.sink.MaxConns() != 24 {
			t.Errorf("limitlar o'zgardi: %d o'rnatish, max_conns=%d", s.sink.sets(), s.sink.MaxConns())
		}
		if s.notes.count() != 0 {
			t.Error("klientga yopilish bildirishnomasi yuborildi")
		}

		calls := ap.callLog()
		if len(calls) < 600 {
			t.Fatalf("2 soatda faqat %d urinish", len(calls))
		}
		if first := calls[0].at.Sub(g.IssuedAt); first > testR {
			t.Errorf("birinchi yangilash %s da, ≤ %s kutilgan", first, testR)
		}
		for i := 1; i < len(calls); i++ {
			gap := calls[i].at.Sub(calls[i-1].at)
			if gap > renewRetryCap || gap < renewRetryCap*8/10 {
				t.Fatalf("%d-urinish oralig'i %s, [8s, 10s] kutilgan", i, gap)
			}
		}
		if !strings.Contains(logs.String(), "[tunnel-renew-failed] myapp.cc01.test:80 err=") {
			t.Errorf("[tunnel-renew-failed] yozilmadi:\n%.300s", logs.String())
		}
		if strings.Contains(logs.String(), testToken) {
			t.Error("token log'ga tushdi")
		}

		// AP qaytdi — keyingi urinish yangi limitlarni olib keladi.
		ap.setState(proGrant)
		ap.setErr(nil)
		time.Sleep(renewRetryCap)
		synctest.Wait()
		if got := s.sink.MaxConns(); got != 128 {
			t.Errorf("AP tiklangach max_conns=%d, 128 kutilgan", got)
		}
		s.stop(t)
	})
}

func TestSupervise_AllowlistedDenialCloses(t *testing.T) {
	for _, code := range []string{
		"TOKEN_INVALID", "TOKEN_REVOKED", "TOKEN_EXPIRED",
		"PLAN_SUSPENDED", "SUBDOMAIN_NOT_OWNED",
	} {
		t.Run(code, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ap := newFakeAP(freeGrant)
				ap.setErr(&access.Denial{Code: code, Message: "rad etildi"})

				g := freeGrant
				g.IssuedAt = time.Now()
				logs := &syncBuffer{}
				j := newSupervisorServer(ap, testR, config.RenewDenyClose, logs)
				s := startSupervisor(j, openRequest("myapp"), &g)

				time.Sleep(testR)
				synctest.Wait()

				if !s.returned() {
					t.Fatal("rad javobidan keyin supervisor qaytmadi")
				}
				d := s.result
				if d == nil || d.Code != code {
					t.Fatalf("%s rad javobi kutilgan, %v olindi", code, d)
				}
				if s.notes.count() != 1 || s.notes.codes[0] != code || s.notes.msgs[0] != "rad etildi" {
					t.Errorf("bildirishnoma: %v %v", s.notes.codes, s.notes.msgs)
				}
				if !strings.Contains(logs.String(), "[tunnel-revoked] myapp.cc01.test:80 code="+code) {
					t.Errorf("[tunnel-revoked] yozilmadi:\n%s", logs.String())
				}
				s.stop(t)
			})
		})
	}
}

// Noma'lum, UNSPECIFIED va vaqtinchalik kodlar tunnelni yopmaydi: buggy
// AP hamma ochiq tunnellarni bir zumda o'chirib yubormasligi kerak.
func TestSupervise_UnknownOrUnspecifiedDenialKeepsTunnel(t *testing.T) {
	for _, code := range []string{
		"UNSPECIFIED", "SOMETHING_NEW", "", "SUBDOMAIN_BUSY",
		"QUOTA_TUNNELS_EXCEEDED", "EMAIL_NOT_VERIFIED", "SUBDOMAIN_INVALID",
		"DOMAIN_NOT_VERIFIED",
	} {
		t.Run("code="+code, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ap := newFakeAP(freeGrant)
				ap.setErr(&access.Denial{Code: code, Message: "x"})

				g := freeGrant
				g.IssuedAt = time.Now()
				j := newSupervisorServer(ap, testR, config.RenewDenyClose, io.Discard)
				s := startSupervisor(j, openRequest("myapp"), &g)

				time.Sleep(5 * time.Minute)
				synctest.Wait()

				if s.returned() {
					t.Fatal("tunnel yopildi")
				}
				if s.notes.count() != 0 {
					t.Error("bildirishnoma yuborildi")
				}
				if n := len(ap.callLog()); n < 9 {
					t.Errorf("rad javobidan keyin yangilash to'xtadi: %d chaqiruv", n)
				}
				if d := s.stop(t); d != nil {
					t.Fatalf("rad javobi qaytdi: %v", d)
				}
			})
		})
	}
}

// CC01_ACCESS_RENEW_DENY=log — dry run: yopiladigan rad javobi faqat
// log'ga yoziladi.
func TestSupervise_DenyModeLogDoesNotClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ap := newFakeAP(freeGrant)
		ap.setErr(&access.Denial{Code: "TOKEN_REVOKED", Message: "token bekor qilingan"})

		g := freeGrant
		g.IssuedAt = time.Now()
		logs := &syncBuffer{}
		j := newSupervisorServer(ap, testR, config.RenewDenyLog, logs)
		s := startSupervisor(j, openRequest("myapp"), &g)

		time.Sleep(5 * time.Minute)
		synctest.Wait()

		if s.returned() {
			t.Fatal("dry run rejimida tunnel yopildi")
		}
		if s.notes.count() != 0 {
			t.Error("dry run rejimida bildirishnoma yuborildi")
		}
		out := logs.String()
		if !strings.Contains(out, "[tunnel-revoke-dryrun] myapp.cc01.test:80 code=TOKEN_REVOKED") {
			t.Errorf("[tunnel-revoke-dryrun] yozilmadi:\n%s", out)
		}
		if strings.Contains(out, "[tunnel-revoked]") {
			t.Error("dry run rejimida [tunnel-revoked] yozildi")
		}
		if d := s.stop(t); d != nil {
			t.Fatalf("rad javobi qaytdi: %v", d)
		}
	})
}

func TestSupervise_DisabledWhenIntervalZeroOrNoRenewer(t *testing.T) {
	t.Run("CC01_ACCESS_RENEW=0", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ap := newFakeAP(proGrant)
			g := freeGrant
			g.IssuedAt = time.Now()
			j := newSupervisorServer(ap, 0, config.RenewDenyClose, io.Discard)
			s := startSupervisor(j, openRequest("myapp"), &g)

			time.Sleep(time.Hour)
			synctest.Wait()

			if n := len(ap.callLog()); n != 0 {
				t.Errorf("yangilash o'chiq, lekin %d chaqiruv", n)
			}
			if s.returned() {
				t.Fatal("klient ketmasdan qaytdi")
			}
			s.stop(t)
		})
	})

	t.Run("AllowAll is not a Renewer", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			allow := &access.AllowAll{Limits: access.Grant{Plan: "disabled", MaxTunnels: 1}}
			g, _ := allow.Authorize(context.Background(), openRequest("myapp"))
			j := newSupervisorServer(allow, testR, config.RenewDenyClose, io.Discard)
			s := startSupervisor(j, openRequest("myapp"), g)

			time.Sleep(time.Hour)
			synctest.Wait()

			if s.returned() || s.sink.sets() != 0 {
				t.Fatal("AllowAll bilan supervisor faol bo'lmasligi kerak")
			}
			s.stop(t)
		})
	})
}

// Klient subdomainni bo'sh qoldirgan: yangilash AP BERGAN nom bilan
// ketadi, aks holda AP yangi nom band qilib yuborardi.
func TestSupervise_SendsGrantedSubdomain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ap := newFakeAP(freeGrant)
		g := freeGrant
		g.Subdomain = "myapp"
		g.IssuedAt = time.Now()
		j := newSupervisorServer(ap, testR, config.RenewDenyClose, io.Discard)
		req := openRequest("")
		req.CliVersion = "0.3.0"
		s := startSupervisor(j, req, &g)

		time.Sleep(testR)
		synctest.Wait()

		calls := ap.callLog()
		if len(calls) == 0 {
			t.Fatal("yangilash bo'lmadi")
		}
		got := calls[0].req
		if got.Subdomain != "myapp" || !got.Renewal {
			t.Errorf("so'rov: subdomain=%q renewal=%v", got.Subdomain, got.Renewal)
		}
		if got.Token != testToken || got.Protocol != "http" || got.CliVersion != "0.3.0" {
			t.Errorf("asl so'rov maydonlari yo'qoldi: %+v", got)
		}
		s.stop(t)
	})
}

// Yangi edge + eski AP: renewal bayrog'i e'tiborsiz qoldiriladi va AP
// oddiy grant qaytaradi — tunnel saqlanadi, limitlar qo'llanadi.
func TestSupervise_OldAPGrantsKeepTunnel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ap := newFakeAP(proGrant)
		g := freeGrant
		g.IssuedAt = time.Now()
		logs := &syncBuffer{}
		j := newSupervisorServer(ap, testR, config.RenewDenyClose, logs)
		s := startSupervisor(j, openRequest("myapp"), &g)

		time.Sleep(10 * time.Minute)
		synctest.Wait()

		if s.returned() {
			t.Fatal("tunnel yopildi")
		}
		if n := len(ap.callLog()); n < 20 {
			t.Errorf("10 daqiqada faqat %d yangilash", n)
		}
		if s.sink.MaxConns() != 128 {
			t.Errorf("max_conns=%d, 128 kutilgan", s.sink.MaxConns())
		}
		// [tunnel-limits] faqat o'zgarishda yoziladi.
		if n := strings.Count(logs.String(), "[tunnel-limits]"); n != 1 {
			t.Errorf("[tunnel-limits] %d marta yozildi, 1 kutilgan:\n%s", n, logs.String())
		}
		if !strings.Contains(logs.String(), "[tunnel-limits] myapp.cc01.test:80 plan=pro max_conns=128") {
			t.Errorf("log:\n%s", logs.String())
		}
		s.stop(t)
	})
}

// Klient ketganda davom etayotgan yangilash bekor qilinadi — tunnel
// tozalanishi AP taymautini kutmaydi.
func TestSupervise_ClientGoneCancelsInFlightRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ap := newFakeAP(freeGrant)
		ap.rpc = time.Hour
		g := freeGrant
		g.IssuedAt = time.Now()
		j := newSupervisorServer(ap, testR, config.RenewDenyClose, io.Discard)
		s := startSupervisor(j, openRequest("myapp"), &g)

		time.Sleep(testR + time.Second)
		synctest.Wait()
		if len(ap.callLog()) != 1 {
			t.Fatal("yangilash boshlanmadi")
		}

		before := time.Now()
		if d := s.stop(t); d != nil {
			t.Fatalf("rad javobi: %v", d)
		}
		if took := time.Since(before); took != 0 {
			t.Errorf("supervisor %s kechikib qaytdi", took)
		}
	})
}

// ─────────────────────── sof funksiyalar ───────────────────────

func TestRenewDelay_Bounds(t *testing.T) {
	now := time.Now()
	const r = 30 * time.Second

	for range 10_000 {
		d := renewDelay(now, now, r)
		if d > r || d < r*8/10 {
			t.Fatalf("yangi grant: %s, [%s, %s] kutilgan", d, r*8/10, r)
		}
		if d := renewDelay(time.Time{}, now, r); d > r || d < r*8/10 {
			t.Fatalf("IssuedAt nol: %s", d)
		}
		if d := renewDelay(now.Add(-r), now, r); d != 0 {
			t.Fatalf("R yoshidagi grant darhol yangilanishi kerak, %s olindi", d)
		}
		if d := renewDelay(now.Add(-time.Hour), now, r); d != 0 {
			t.Fatalf("eski grant: %s", d)
		}
		if d := renewDelay(now.Add(-10*time.Second), now, r); d > 20*time.Second {
			t.Fatalf("10 s yoshidagi grant: %s > 20s", d)
		}
	}
}

func TestRenewInterval(t *testing.T) {
	cases := []struct {
		cfg, lease, want time.Duration
	}{
		{30 * time.Second, time.Minute, 30 * time.Second},
		{50 * time.Second, time.Minute, 30 * time.Second}, // LeaseTTL/2 chegarasi
		{10 * time.Second, time.Minute, 10 * time.Second},
		{30 * time.Second, 0, 30 * time.Second}, // AP lease bermagan
		{0, time.Minute, 0},                     // o'chirilgan
	}
	for _, tc := range cases {
		if got := renewInterval(tc.cfg, tc.lease); got != tc.want {
			t.Errorf("renewInterval(%s, %s) = %s, %s kutilgan", tc.cfg, tc.lease, got, tc.want)
		}
	}
}

func TestClosesTunnel_Allowlist(t *testing.T) {
	closing := map[string]bool{
		"TOKEN_INVALID": true, "TOKEN_REVOKED": true, "TOKEN_EXPIRED": true,
		"PLAN_SUSPENDED": true, "SUBDOMAIN_NOT_OWNED": true,
	}
	for _, code := range []string{
		"TOKEN_INVALID", "TOKEN_REVOKED", "TOKEN_EXPIRED", "PLAN_SUSPENDED",
		"SUBDOMAIN_NOT_OWNED", "UNSPECIFIED", "", "SUBDOMAIN_BUSY",
		"QUOTA_TUNNELS_EXCEEDED", "EMAIL_NOT_VERIFIED", "token_revoked",
	} {
		if got := closesTunnel(code); got != closing[code] {
			t.Errorf("closesTunnel(%q) = %v", code, got)
		}
	}
}

// 60 s kafolati konfiguratsiyada yashaydi.
func TestDefaultConfigMeetsSLO(t *testing.T) {
	if b := config.DefaultAccessRenew + config.DefaultAccessTimeout; b != 33*time.Second {
		t.Errorf("standart chegara %s, 33s kutilgan", b)
	}
	// AP yiqilib qaytgandan keyin kanal qayta ulanishi ham qo'shiladi.
	if b := config.AccessReconnectMax + config.DefaultAccessRenew + config.DefaultAccessTimeout; b >= config.AccessSLO {
		t.Errorf("standart chegara (qayta ulanish bilan) %s >= %s", b, config.AccessSLO)
	}
	// Eng yomon holat — sozlamaning yuqori chegarasi. Keshdan ochilgan
	// tunnel ko'pi bilan R yoshidagi natija bilan boshlaydi (kesh yangiligi
	// R = min(CC01_ACCESS_RENEW, LeaseTTL/2) bilan cheklangan) va R ≤
	// CC01_ACCESS_RENEW.
	if b := config.AccessReconnectMax + config.MaxAccessRenew + config.DefaultAccessTimeout; b >= config.AccessSLO {
		t.Errorf("CC01_ACCESS_RENEW chegarasi %s >= %s", b, config.AccessSLO)
	}
	if r := renewInterval(config.MaxAccessRenew, time.Minute); r > config.MaxAccessRenew {
		t.Errorf("R=%s sozlamadan katta", r)
	}
}

// ───────────────── loopback TCP orqali integratsiya ─────────────────

type serveHarness struct {
	j    *CC01Server
	addr string
	logs *syncBuffer
	done chan error // har serveEventConn tugashi

	mu      sync.Mutex
	clients []net.Conn
}

func newServeHarness(t *testing.T, auth access.Authorizer, renew time.Duration) *serveHarness {
	t.Helper()

	h := &serveHarness{logs: &syncBuffer{}, done: make(chan error, 32)}
	h.j = &CC01Server{
		config: config.Config{
			DomainName:       "cc01.test",
			MaxConsPerTunnel: 24,
			AccessRenew:      renew,
			AccessRenewDeny:  config.RenewDenyClose,
		},
		authorizer: auth,
		logOut:     h.logs,
	}
	h.j.initRegistry()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.done <- h.j.serveEventConn(conn)
			}()
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		h.mu.Lock()
		for _, c := range h.clients {
			_ = c.Close()
		}
		h.mu.Unlock()
		wg.Wait()
		if strings.Contains(h.logs.String(), testToken) {
			t.Error("token log'ga tushdi")
		}
	})
	return h
}

// open klient sifatida tunnel so'raydi va birinchi javob freymini qaytaradi.
func (h *serveHarness) open(t *testing.T, proto cc01v1.Protocol, subdomain string) (net.Conn, *cc01v1.TunnelOpened) {
	t.Helper()

	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.clients = append(h.clients, conn)
	h.mu.Unlock()

	if err := events.WritePreamble(conn); err != nil {
		t.Fatal(err)
	}
	if err := events.WriteTunnelRequested(conn, &cc01v1.TunnelRequested{
		Protocol:   proto,
		Subdomain:  subdomain,
		Token:      testToken,
		CliVersion: "test",
	}); err != nil {
		t.Fatal(err)
	}

	frame := readFrame(t, conn)
	opened := frame.GetTunnelOpened()
	if opened == nil {
		t.Fatalf("TunnelOpened kutilgan edi, %v olindi", frame)
	}
	return conn, opened
}

func readFrame(t *testing.T, conn net.Conn) *cc01v1.Frame {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	frame, err := events.ReadFrame(conn)
	if err != nil {
		t.Fatalf("freym o'qilmadi: %v", err)
	}
	return frame
}

// waitServeDone bitta serveEventConn tugashini kutadi.
func (h *serveHarness) waitServeDone(t *testing.T, within time.Duration) error {
	t.Helper()
	select {
	case err := <-h.done:
		return err
	case <-time.After(within):
		t.Fatalf("serveEventConn %s ichida qaytmadi", within)
		return nil
	}
}

func (h *serveHarness) registrySizes() (http, tcp, cnames, tenants int) {
	h.j.tunnelsMx.RLock()
	defer h.j.tunnelsMx.RUnlock()
	return len(h.j.httpTunnels), len(h.j.tcpTunnels), len(h.j.cnameMap), len(h.j.tenantTunnels)
}

func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s ichida bajarilmadi: %s", within, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

const loopbackR = 50 * time.Millisecond

func TestServe_RenewalAppliesNewLimitsToOpenTunnel(t *testing.T) {
	ap := newFakeAP(freeGrant)
	h := newServeHarness(t, ap, loopbackR)

	_, opened := h.open(t, cc01v1.Protocol_PROTOCOL_HTTP, "demo")
	if opened.GetErrorCode() != "" {
		t.Fatalf("tunnel ochilmadi: %s", opened.GetErrorMessage())
	}
	const host = "demo.cc01.test"

	maxConns := func() int {
		h.j.tunnelsMx.RLock()
		defer h.j.tunnelsMx.RUnlock()
		if tn, ok := h.j.httpTunnels[host]; ok {
			return tn.MaxConns()
		}
		return -1
	}
	if got := maxConns(); got != 24 {
		t.Fatalf("ochilishda max_conns=%d, 24 kutilgan", got)
	}

	ap.setState(proGrant)
	eventually(t, 5*time.Second, "max_conns 128 bo'ldi", func() bool { return maxConns() == 128 })

	// Log limit o'rnatilgandan keyin yoziladi — uni ham kutamiz.
	eventually(t, 5*time.Second, "[tunnel-limits] yozildi", func() bool {
		return strings.Contains(h.logs.String(), "[tunnel-limits] demo.cc01.test:80 plan=pro max_conns=128")
	})
	for _, c := range ap.callLog() {
		if c.req.Subdomain != "demo" || !c.req.Renewal {
			t.Fatalf("yangilash so'rovi: %+v", c.req)
		}
	}
}

func TestServe_DenialSendsClosureFrameAndCleansUp(t *testing.T) {
	ap := newFakeAP(freeGrant)
	h := newServeHarness(t, ap, loopbackR)

	control, opened := h.open(t, cc01v1.Protocol_PROTOCOL_TCP, "dbx")
	if opened.GetErrorCode() != "" {
		t.Fatalf("tunnel ochilmadi: %s", opened.GetErrorMessage())
	}

	// Ommaviy ulanish → ConnectionReceived → xususiy ulanish: juftlik.
	public, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", opened.GetPublicPort()))
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()

	received := readFrame(t, control).GetConnectionReceived()
	if received == nil {
		t.Fatal("ConnectionReceived kutilgan edi")
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

	if _, err := public.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	_ = private.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(private, got); err != nil || string(got) != "ping" {
		t.Fatalf("juftlik ishlamadi: %q %v", got, err)
	}

	// Tenant to'xtatildi.
	ap.setErr(&access.Denial{Code: "PLAN_SUSPENDED", Message: "hisob to'xtatilgan"})

	_ = control.SetReadDeadline(time.Now().Add(5 * time.Second))
	closure, err := events.ReadFrame(control)
	if err != nil {
		t.Fatalf("yopilish freymi kelmadi: %v", err)
	}
	notice := closure.GetTunnelOpened()
	if notice == nil || notice.GetErrorCode() != "PLAN_SUSPENDED" || notice.GetErrorMessage() == "" {
		t.Fatalf("yopilish freymi noto'g'ri: %v", closure)
	}
	if _, err := events.ReadFrame(control); !errors.Is(err, io.EOF) {
		t.Fatalf("yopilish freymidan keyin EOF kutilgan, %v olindi", err)
	}

	if err := h.waitServeDone(t, 5*time.Second); err == nil || !strings.Contains(err.Error(), "PLAN_SUSPENDED") {
		t.Errorf("serveEventConn rad javobini qaytarmadi: %v", err)
	}
	if hs, tc, cn, tn := h.registrySizes(); hs+tc+cn+tn != 0 {
		t.Errorf("ro'yxat tozalanmadi: http=%d tcp=%d cname=%d tenant=%d", hs, tc, cn, tn)
	}

	// Ko'priklangan juftlik ham yopilgan.
	for name, c := range map[string]net.Conn{"public": public, "private": private} {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s ulanish ochiq qoldi", name)
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Errorf("%s ulanish yopilmadi (timeout)", name)
		}
	}

	if !strings.Contains(h.logs.String(), "[tunnel-revoked] dbx.cc01.test:") {
		t.Errorf("[tunnel-revoked] yozilmadi:\n%s", h.logs.String())
	}
}

func TestServe_TenantTunnelLimitAtOpen(t *testing.T) {
	t.Run("tenant limit", func(t *testing.T) {
		ap := newFakeAP(freeGrant) // MaxTunnels: 1
		h := newServeHarness(t, ap, loopbackR)

		first, opened := h.open(t, cc01v1.Protocol_PROTOCOL_HTTP, "aaa")
		if opened.GetErrorCode() != "" {
			t.Fatalf("1-tunnel ochilmadi: %s", opened.GetErrorMessage())
		}

		_, denied := h.open(t, cc01v1.Protocol_PROTOCOL_TCP, "bbb")
		if denied.GetErrorCode() != "QUOTA_TUNNELS_EXCEEDED" {
			t.Fatalf("QUOTA_TUNNELS_EXCEEDED kutilgan, %q olindi", denied.GetErrorCode())
		}
		h.waitServeDone(t, 5*time.Second) // rad etilgan ulanish
		if hs, tc, _, _ := h.registrySizes(); hs != 1 || tc != 0 {
			t.Errorf("rad etilgan tunnel ro'yxatda qoldi: http=%d tcp=%d", hs, tc)
		}

		_ = first.Close()
		h.waitServeDone(t, 5*time.Second)
		if _, _, _, tn := h.registrySizes(); tn != 0 {
			t.Fatalf("tenant hisoblagichi bo'shamadi: %d", tn)
		}

		_, third := h.open(t, cc01v1.Protocol_PROTOCOL_HTTP, "ccc")
		if third.GetErrorCode() != "" {
			t.Fatalf("1-tunnel yopilgach 3-tunnel ochilmadi: %s", third.GetErrorCode())
		}
	})

	// AllowAll (TenantID "") hisoblanmaydi — tunnel-demo shunday ishlaydi.
	t.Run("TenantID empty is exempt", func(t *testing.T) {
		allow := &access.AllowAll{Limits: access.Grant{Plan: "disabled", MaxTunnels: 1, MaxConnsPerTunnel: 24}}
		h := newServeHarness(t, allow, 0)

		for _, sub := range []string{"aaa", "bbb", "ccc"} {
			if _, opened := h.open(t, cc01v1.Protocol_PROTOCOL_HTTP, sub); opened.GetErrorCode() != "" {
				t.Fatalf("%s ochilmadi: %s", sub, opened.GetErrorCode())
			}
		}
		if hs, _, _, tn := h.registrySizes(); hs != 3 || tn != 0 {
			t.Errorf("http=%d tenant=%d", hs, tn)
		}
	})
}

// Klient ketganda serveEventConn darhol qaytadi — eski sikl
// net.ErrClosed da aylanib qolardi. Davom etayotgan yangilash ham kutilmaydi.
func TestServe_ClientDisconnectReturnsPromptly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		renew time.Duration
		rpc   time.Duration
	}{
		{"renew disabled", 0, 0},
		{"renewal in flight", loopbackR, time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ap := newFakeAP(freeGrant)
			ap.rpc = tc.rpc
			h := newServeHarness(t, ap, tc.renew)

			conn, opened := h.open(t, cc01v1.Protocol_PROTOCOL_HTTP, "demo")
			if opened.GetErrorCode() != "" {
				t.Fatalf("tunnel ochilmadi: %s", opened.GetErrorMessage())
			}
			if tc.rpc > 0 {
				eventually(t, 5*time.Second, "yangilash boshlandi", func() bool { return len(ap.callLog()) > 0 })
			}

			started := time.Now()
			_ = conn.Close()
			if err := h.waitServeDone(t, time.Second); err != nil {
				t.Errorf("kutilmagan xato: %v", err)
			}
			if took := time.Since(started); took > time.Second {
				t.Errorf("%s da qaytdi", took)
			}
			if hs, tcp, cn, tn := h.registrySizes(); hs+tcp+cn+tn != 0 {
				t.Errorf("ro'yxat tozalanmadi: http=%d tcp=%d cname=%d tenant=%d", hs, tcp, cn, tn)
			}
			if !strings.Contains(h.logs.String(), "[tunnel-closed] demo.cc01.test:80") {
				t.Errorf("[tunnel-closed] yozilmadi:\n%s", h.logs.String())
			}
		})
	}
}

// TCP tunnel porti Close'dan oldin olinadi: aks holda ro'yxatdan
// o'chirish 0-port bilan urinib, yozuvni abadiy qoldirardi.
func TestServe_TCPRegistryCleanedOnClose(t *testing.T) {
	ap := newFakeAP(freeGrant)
	h := newServeHarness(t, ap, loopbackR)

	conn, opened := h.open(t, cc01v1.Protocol_PROTOCOL_TCP, "dbx")
	if opened.GetErrorCode() != "" {
		t.Fatalf("tunnel ochilmadi: %s", opened.GetErrorMessage())
	}
	port := uint16(opened.GetPublicPort())
	if port == 0 {
		t.Fatal("ommaviy port 0")
	}

	h.j.tunnelsMx.RLock()
	_, registered := h.j.tcpTunnels[port]
	h.j.tunnelsMx.RUnlock()
	if !registered {
		t.Fatalf("tcpTunnels[%d] yo'q", port)
	}
	if want := fmt.Sprintf("dbx.cc01.test:%d", port); opened.GetTunnelId() != want {
		t.Errorf("tunnel ID %q, %q kutilgan", opened.GetTunnelId(), want)
	}

	// Accept sikli ishlayotganiga ishonch hosil qilamiz (server.TCPServer
	// Start/Stop poygasi — open_issues ga qarang).
	probe, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if readFrame(t, conn).GetConnectionReceived() == nil {
		t.Fatal("ConnectionReceived kutilgan edi")
	}

	_ = conn.Close()
	h.waitServeDone(t, 5*time.Second)

	if hs, tcp, cn, tn := h.registrySizes(); hs+tcp+cn+tn != 0 {
		t.Errorf("ro'yxat tozalanmadi: http=%d tcp=%d cname=%d tenant=%d", hs, tcp, cn, tn)
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
		c.Close()
		t.Error("ommaviy port yopilmadi")
	}
}
