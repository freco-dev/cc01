package usage

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/freco-dev/cc01/core-server/access"
	"github.com/freco-dev/cc01/core-server/tunnel"
)

// ─────────────────────────── soxta AP ───────────────────────────

// fakeReporter — AP o'rniga. delivered — AP QABUL QILGAN oynalar
// (har chaqiruvda batch'ning birinchi `accepted` tasi), tartib bilan.
type fakeReporter struct {
	mu        sync.Mutex
	err       error
	accept    func(n int) int // nil — hammasi
	block     chan struct{}   // nil bo'lmasa chaqiruv shu yopilguncha kutadi
	calls     []int
	delivered []access.UsageWindow
}

func (f *fakeReporter) ReportUsage(_ context.Context, windows []access.UsageWindow) (int, error) {
	f.mu.Lock()
	block := f.block
	f.mu.Unlock()
	if block != nil {
		<-block
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, len(windows))
	if f.err != nil {
		return 0, f.err
	}
	n := len(windows)
	if f.accept != nil {
		n = f.accept(n)
	}
	f.delivered = append(f.delivered, windows[:min(n, len(windows))]...)
	return n, nil
}

func (f *fakeReporter) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeReporter) callSizes() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeReporter) got() []access.UsageWindow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.delivered)
}

// fakeSource — tunnelning kumulyativ hisoblagichlari.
type fakeSource struct {
	mu sync.Mutex
	u  tunnel.Usage
}

func (s *fakeSource) add(in, out, conns, rejected uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.u.BytesIn += in
	s.u.BytesOut += out
	s.u.Connections += conns
	s.u.Rejected += rejected
}

func (s *fakeSource) usage() tunnel.Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.u
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) logf(format string, args ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fmt.Fprintf(&b.buf, format+"\n", args...)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newTestMeter(rep access.UsageReporter, interval time.Duration, logs *logBuffer, queueMax int) *Meter {
	return New(Options{
		Reporter: rep,
		Interval: interval,
		Logf:     logs.logf,
		QueueMax: queueMax,
	})
}

// sleepUntil virtual vaqtni unix sekund + frac gacha suradi va pufak
// tinchishini kutadi (synctest ichida).
func sleepUntil(unix int64, frac time.Duration) {
	time.Sleep(time.Unix(unix, 0).Add(frac).Sub(time.Now()))
	synctest.Wait()
}

func win(id string, start, end int64, in, out uint64, conns, rejected uint32) access.UsageWindow {
	return access.UsageWindow{
		TenantID: "acme", TunnelID: id, WindowStart: start, WindowEnd: end,
		BytesIn: in, BytesOut: out, Connections: conns, Rejected: rejected,
	}
}

func pushWindows(m *Meter, windows ...access.UsageWindow) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enqueueLocked(windows...)
}

func queueLen(m *Meter) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.queue)
}

func queuedWindows(m *Meter) []access.UsageWindow {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]access.UsageWindow, len(m.queue))
	for i, q := range m.queue {
		out[i] = q.w
	}
	return out
}

func diffWindows(t *testing.T, got, want []access.UsageWindow) {
	t.Helper()
	if !slices.Equal(got, want) {
		var b strings.Builder
		fmt.Fprintf(&b, "oynalar mos emas\nolindi (%d):\n", len(got))
		for _, w := range got {
			fmt.Fprintf(&b, "  %+v\n", w)
		}
		fmt.Fprintf(&b, "kutilgan (%d):\n", len(want))
		for _, w := range want {
			fmt.Fprintf(&b, "  %+v\n", w)
		}
		t.Fatal(b.String())
	}
}

// ─────────────────────────── oyna kesish ───────────────────────────

// Oynalar devor soatiga tekislangan: birinchisi ochilish sekundidan
// keyingi chegaragacha (qisman), o'rtadagilari to'liq (trafiksizi ham),
// oxirgisi yopilish sekundigacha (qisman). Ustma-ust tushmaydi va
// uzluksiz.
func TestMeter_AlignedWindowsWithPartialFirstAndLast(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// synctest soati 2000-01-01 00:00:00 UTC dan boshlanadi — 60 ga karrali.
		t0 := time.Now().Unix()
		if t0%60 != 0 {
			t.Fatalf("boshlang'ich vaqt tekislanmagan: %d", t0)
		}

		rep := &fakeReporter{}
		logs := &logBuffer{}
		m := newTestMeter(rep, time.Minute, logs, 0)
		m.Start()

		sleepUntil(t0+13, 500*time.Millisecond)
		src := &fakeSource{}
		closer := m.Open("web.cc01.test:80/aa", "acme", src.usage)

		sleepUntil(t0+20, 0)
		src.add(100, 1000, 2, 1)
		sleepUntil(t0+59, 900*time.Millisecond)
		src.add(5, 0, 0, 0)

		// t0+60: 1-oyna [13, 60) yuborildi.
		sleepUntil(t0+60, 100*time.Millisecond)
		diffWindows(t, rep.got(), []access.UsageWindow{
			win("web.cc01.test:80/aa", t0+13, t0+60, 105, 1000, 2, 1),
		})

		// t0+120: trafiksiz to'liq oyna ham yuboriladi.
		sleepUntil(t0+120, 100*time.Millisecond)
		src.add(0, 7, 1, 0)
		sleepUntil(t0+145, 700*time.Millisecond)
		closer()
		closer() // qayta chaqirish — no-op

		// Yakuniy oyna navbatda, keyingi tikda ketadi.
		sleepUntil(t0+180, 100*time.Millisecond)
		diffWindows(t, rep.got(), []access.UsageWindow{
			win("web.cc01.test:80/aa", t0+13, t0+60, 105, 1000, 2, 1),
			win("web.cc01.test:80/aa", t0+60, t0+120, 0, 0, 0, 0),
			win("web.cc01.test:80/aa", t0+120, t0+145, 0, 7, 1, 0),
		})

		// Tunnel yopilgach yangi oyna yo'q.
		sleepUntil(t0+240, 100*time.Millisecond)
		if n := len(rep.got()); n != 3 {
			t.Fatalf("yopilgandan keyin oyna qo'shildi: %d", n)
		}
		m.Stop(time.Second)

		if out := logs.String(); !strings.Contains(out, "[usage-reported] windows=1 accepted=1") {
			t.Errorf("[usage-reported] yo'q:\n%s", out)
		}
		// Bo'sh tiklarda log yozilmaydi: 3 ta yuborishli tik (60, 120, 180).
		if n := strings.Count(logs.String(), "[usage-reported]"); n != 3 {
			t.Errorf("[usage-reported] %d marta, 3 kutilgan:\n%s", n, logs.String())
		}
	})
}

// < 1 s oynalar: chegara sekundida ochilgan tunnel uchun o'sha chegarada
// oyna kesilmaydi (trafik keyingisiga qo'shiladi); bir sekund ichida
// ochilib-yopilgan yoki chegaradan < 1 s keyin yopilgan tunnelning
// yakuniy oynasi 1 s ga cho'ziladi — trafik yo'qolmaydi.
func TestMeter_SubSecondWindows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t0 := time.Now().Unix()
		rep := &fakeReporter{}
		m := newTestMeter(rep, 5*time.Second, &logBuffer{}, 0)

		// (a) Chegara sekundida ochildi: cutAll(o'sha chegara) — oyna yo'q.
		sleepUntil(t0+10, 300*time.Millisecond)
		a := &fakeSource{}
		m.Open("a", "acme", a.usage)
		a.add(1, 1, 1, 0)
		m.cutAll(t0 + 10)
		if n := queueLen(m); n != 0 {
			t.Fatalf("nol uzunlikdagi oyna kesildi: %d", n)
		}
		a.add(2, 2, 0, 0)
		m.cutAll(t0 + 15)

		// (b) Bir sekund ichida ochilib-yopildi.
		sleepUntil(t0+15, 100*time.Millisecond)
		b := &fakeSource{}
		closeB := m.Open("b", "acme", b.usage)
		b.add(9, 0, 1, 0)
		sleepUntil(t0+15, 800*time.Millisecond)
		closeB()

		// (c) Chegaradan keyin < 1 s ichida to'xtatildi: a ning yakuniy
		// oynasi [20, 21) bo'ladi.
		sleepUntil(t0+20, 0)
		m.cutAll(t0 + 20)
		sleepUntil(t0+20, 400*time.Millisecond)
		a.add(4, 0, 0, 0)

		got := queuedWindows(m)
		want := []access.UsageWindow{
			win("a", t0+10, t0+15, 3, 3, 1, 0),
			win("b", t0+15, t0+16, 9, 0, 1, 0),
			win("a", t0+15, t0+20, 0, 0, 0, 0),
		}
		diffWindows(t, got, want)

		m.Stop(time.Second)
		diffWindows(t, rep.got(), append(want, win("a", t0+20, t0+21, 4, 0, 0, 0)))
	})
}

// Tasodifiy ochilish/yopilish va trafik bilan: har tunnelning oynalari
// ochilish sekundidan yopilish sekundigacha uzluksiz, ustma-ust tushmaydi,
// bo'sh emas va (oxirgisidan tashqari) tekislangan chegaralarda tugaydi;
// yig'indilar aniq.
func TestMeter_WindowsContiguousNoOverlapRandomized(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = 5
		rng := rand.New(rand.NewPCG(1, 2))
		rep := &fakeReporter{}
		m := newTestMeter(rep, interval*time.Second, &logBuffer{}, 0)
		m.Start()

		type tun struct {
			id                  string
			src                 *fakeSource
			opened, closed      time.Time
			closer              func()
			in, out, conns, rej uint64
		}
		var all []*tun
		var live []*tun
		start := time.Now()
		for step := 0; step < 400; step++ {
			time.Sleep(time.Duration(rng.IntN(3000)) * time.Millisecond)
			synctest.Wait()
			switch r := rng.IntN(10); {
			case r < 3 || len(live) == 0:
				tn := &tun{id: fmt.Sprintf("t%d", len(all)), src: &fakeSource{}, opened: time.Now()}
				tn.closer = m.Open(tn.id, "acme", tn.src.usage)
				all = append(all, tn)
				live = append(live, tn)
			case r < 5:
				i := rng.IntN(len(live))
				tn := live[i]
				tn.closed = time.Now()
				tn.closer()
				live = slices.Delete(live, i, i+1)
			default:
				tn := live[rng.IntN(len(live))]
				in, out := uint64(rng.IntN(5000)), uint64(rng.IntN(5000))
				c, rj := uint64(rng.IntN(3)), uint64(rng.IntN(2))
				tn.src.add(in, out, c, rj)
				tn.in, tn.out, tn.conns, tn.rej = tn.in+in, tn.out+out, tn.conns+c, tn.rej+rj
			}
		}
		for _, tn := range live {
			tn.closed = time.Now()
			tn.closer()
		}
		time.Sleep(2 * interval * time.Second)
		synctest.Wait()
		m.Stop(time.Second)
		if time.Since(start) < time.Minute {
			t.Fatal("sinov juda qisqa")
		}

		byID := make(map[string][]access.UsageWindow)
		for _, w := range rep.got() {
			byID[w.TunnelID] = append(byID[w.TunnelID], w)
		}
		for _, tn := range all {
			ws := byID[tn.id]
			if len(ws) == 0 {
				t.Fatalf("%s: oyna yo'q", tn.id)
			}
			if ws[0].WindowStart != tn.opened.Unix() {
				t.Errorf("%s: birinchi oyna %d dan, ochilish %d", tn.id, ws[0].WindowStart, tn.opened.Unix())
			}
			last := ws[len(ws)-1]
			if want := max(tn.closed.Unix(), last.WindowStart+1); last.WindowEnd != want {
				t.Errorf("%s: oxirgi oyna %d da tugadi, %d kutilgan", tn.id, last.WindowEnd, want)
			}
			var in, out, conns, rej uint64
			for i, w := range ws {
				if w.WindowEnd <= w.WindowStart {
					t.Errorf("%s: bo'sh oyna %+v", tn.id, w)
				}
				if i > 0 && w.WindowStart != ws[i-1].WindowEnd {
					t.Errorf("%s: uzilish yoki ustma-ust: %+v → %+v", tn.id, ws[i-1], w)
				}
				if i < len(ws)-1 && w.WindowEnd%interval != 0 {
					t.Errorf("%s: oyna chegarasi tekislanmagan: %+v", tn.id, w)
				}
				in, out = in+w.BytesIn, out+w.BytesOut
				conns, rej = conns+uint64(w.Connections), rej+uint64(w.Rejected)
			}
			if in != tn.in || out != tn.out || conns != tn.conns || rej != tn.rej {
				t.Errorf("%s: yig'indi %d/%d/%d/%d, kutilgan %d/%d/%d/%d",
					tn.id, in, out, conns, rej, tn.in, tn.out, tn.conns, tn.rej)
			}
		}
	})
}

// ─────────────────────────── yuborish ───────────────────────────

// Navbat ≤ 500 lik bo'laklarda, tartib bilan yuboriladi.
func TestMeter_BatchesOfAtMost500(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rep := &fakeReporter{}
		logs := &logBuffer{}
		m := newTestMeter(rep, 5*time.Second, logs, 0)

		var want []access.UsageWindow
		for i := range 1201 {
			want = append(want, win("x", int64(i), int64(i+1), uint64(i), 0, 0, 0))
		}
		pushWindows(m, want...)
		m.flush(context.Background())

		if got := rep.callSizes(); !slices.Equal(got, []int{500, 500, 201}) {
			t.Fatalf("bo'laklar: %v", got)
		}
		diffWindows(t, rep.got(), want)
		if n := queueLen(m); n != 0 {
			t.Fatalf("navbat bo'shamadi: %d", n)
		}
		if !strings.Contains(logs.String(), "[usage-reported] windows=1201 accepted=1201") {
			t.Errorf("log:\n%s", logs.String())
		}
	})
}

// AP yo'q: oynalar navbatda qoladi, har tikda qayta urinadi; AP
// qaytgach har oyna aynan bir marta, tartib bilan yetkaziladi.
func TestMeter_RetryKeepsWindowsAndDeliversOnceInOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t0 := time.Now().Unix()
		rep := &fakeReporter{}
		rep.setErr(fmt.Errorf("%w: rpc error: code = Unavailable", access.ErrUnavailable))
		logs := &logBuffer{}
		m := newTestMeter(rep, 5*time.Second, logs, 0)
		m.Start()

		src := &fakeSource{}
		closer := m.Open("t", "acme", src.usage)
		for i := range 4 {
			src.add(uint64(i+1), 0, 0, 0)
			sleepUntil(t0+int64(5*(i+1)), 100*time.Millisecond)
		}
		if n := len(rep.got()); n != 0 {
			t.Fatalf("AP yo'q paytda %d oyna yetkazildi", n)
		}
		if n := queueLen(m); n != 4 {
			t.Fatalf("navbatda %d oyna, 4 kutilgan", n)
		}
		if calls := len(rep.callSizes()); calls != 4 {
			t.Fatalf("har tikda bitta urinish kutilgan, %d", calls)
		}
		if !strings.Contains(logs.String(), "[usage-report-failed] queued=4 err=access-server mavjud emas") {
			t.Errorf("log:\n%s", logs.String())
		}
		if strings.Contains(logs.String(), "[usage-reported]") {
			t.Errorf("muvaffaqiyatsiz tikda [usage-reported] yozilmasligi kerak:\n%s", logs.String())
		}

		rep.setErr(nil)
		sleepUntil(t0+25, 100*time.Millisecond)
		closer()
		sleepUntil(t0+30, 100*time.Millisecond)
		m.Stop(time.Second)

		diffWindows(t, rep.got(), []access.UsageWindow{
			win("t", t0, t0+5, 1, 0, 0, 0),
			win("t", t0+5, t0+10, 2, 0, 0, 0),
			win("t", t0+10, t0+15, 3, 0, 0, 0),
			win("t", t0+15, t0+20, 4, 0, 0, 0),
			win("t", t0+20, t0+25, 0, 0, 0, 0),
			win("t", t0+25, t0+26, 0, 0, 0, 0), // yopilish chegara sekundida → 1 s
		})
	})
}

// AP bo'lakning faqat bir qismini qabul qilsa: shuncha oyna o'chiriladi,
// qolgani keyingi tikda qayta yuboriladi — dublikatsiz, tartib bilan.
func TestMeter_PartialAcceptRetriesRest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rep := &fakeReporter{accept: func(n int) int { return min(n, 3) }}
		logs := &logBuffer{}
		m := newTestMeter(rep, 5*time.Second, logs, 0)

		var want []access.UsageWindow
		for i := range 8 {
			want = append(want, win("x", int64(i), int64(i+1), 0, 0, 0, 0))
		}
		pushWindows(m, want...)

		m.flush(context.Background())
		if n := queueLen(m); n != 5 {
			t.Fatalf("1-tikdan keyin navbat %d, 5 kutilgan", n)
		}
		if !strings.Contains(logs.String(), "[usage-reported] windows=8 accepted=3") {
			t.Errorf("log:\n%s", logs.String())
		}
		m.flush(context.Background())
		m.flush(context.Background())
		if n := queueLen(m); n != 0 {
			t.Fatalf("navbat bo'shamadi: %d", n)
		}
		diffWindows(t, rep.got(), want)

		// AP len(batch) dan ko'p yoki manfiy qaytarsa ham navbat buzilmaydi.
		rep.mu.Lock()
		rep.accept = func(n int) int { return n + 10 }
		rep.mu.Unlock()
		pushWindows(m, win("y", 0, 1, 0, 0, 0, 0))
		pushWindows(m, win("y", 1, 2, 0, 0, 0, 0))
		m.flush(context.Background())
		if n := queueLen(m); n != 0 {
			t.Fatalf("navbat: %d", n)
		}
	})
}

// Navbat to'lsa ENG ESKI oynalar tashlanadi va log'ga yoziladi.
func TestMeter_QueueOverflowDropsOldest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rep := &fakeReporter{}
		logs := &logBuffer{}
		m := newTestMeter(rep, 5*time.Second, logs, 10)
		if m.queueMax != 10 {
			t.Fatalf("queueMax=%d", m.queueMax)
		}

		var all []access.UsageWindow
		for i := range 15 {
			all = append(all, win("x", int64(i), int64(i+1), 0, 0, 0, 0))
		}
		if dropped := pushWindows(m, all...); dropped != 5 {
			t.Fatalf("tashlangan: %d", dropped)
		}
		diffWindows(t, queuedWindows(m), all[5:])

		// Meter orqali ham: kesish navbatni to'ldirsa log yoziladi.
		src := &fakeSource{}
		m.Open("tun", "acme", src.usage)
		time.Sleep(3 * time.Second)
		m.cutAll(time.Now().Unix())
		if !strings.Contains(logs.String(), "[usage-dropped] n=1 (navbat to'la)") {
			t.Errorf("log:\n%s", logs.String())
		}
		if got := queuedWindows(m); got[0] != all[6] || got[9].TunnelID != "tun" {
			t.Errorf("navbat: %+v", got)
		}
		m.Stop(time.Second)
	})
}

// Yuborish davomida navbat to'lib, eng eskilari (yo'ldagi bo'lakdan)
// tashlansa ham, qabul qilingan oynalar seq bo'yicha to'g'ri o'chiriladi:
// yangi oynalar yo'qolmaydi.
func TestMeter_DropDuringInFlightSend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		rep := &fakeReporter{block: release}
		m := newTestMeter(rep, 5*time.Second, &logBuffer{}, 4)

		var all []access.UsageWindow
		for i := range 7 {
			all = append(all, win("x", int64(i), int64(i+1), 0, 0, 0, 0))
		}
		pushWindows(m, all[:4]...)

		done := make(chan struct{})
		go func() {
			defer close(done)
			m.flush(context.Background())
		}()
		synctest.Wait() // flush 4 ta oynani yubordi va AP'da kutyapti

		pushWindows(m, all[4:]...) // 0..2 tashlanadi
		diffWindows(t, queuedWindows(m), all[3:])

		rep.mu.Lock()
		rep.block = nil
		rep.mu.Unlock()
		close(release)
		<-done

		// 1-bo'lak (0..3) qabul qilindi: navbatdan faqat 3 o'chadi, keyin
		// 4..6 ikkinchi bo'lakda ketadi.
		if n := queueLen(m); n != 0 {
			t.Fatalf("navbat: %+v", queuedWindows(m))
		}
		diffWindows(t, rep.got(), all)
	})
}

// To'xtashda hali ochiq tunnellarning oynalari hozirgacha kesiladi va
// navbat best-effort yuboriladi; shundan keyin Meter hech narsa qilmaydi.
func TestMeter_StopFlushesOpenTunnels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		t0 := time.Now().Unix()
		rep := &fakeReporter{}
		m := newTestMeter(rep, time.Minute, &logBuffer{}, 0)
		m.Start()

		src := &fakeSource{}
		closer := m.Open("t", "acme", src.usage)
		sleepUntil(t0+30, 0)
		src.add(10, 20, 1, 0)
		m.Stop(time.Second)

		diffWindows(t, rep.got(), []access.UsageWindow{win("t", t0, t0+30, 10, 20, 1, 0)})

		closer()
		late := m.Open("late", "acme", src.usage)
		late()
		m.Stop(time.Second)
		if n := len(rep.got()); n != 1 {
			t.Fatalf("to'xtagandan keyin oyna qo'shildi: %d", n)
		}
	})
}

// AP to'xtashda ham javob bermasa — Stop flushTimeout dan oshmaydi.
func TestMeter_StopFlushIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newTestMeter(&hangingReporter{}, time.Minute, &logBuffer{}, 0)
		m.Start()
		m.Open("t", "acme", (&fakeSource{}).usage)
		time.Sleep(time.Second)

		started := time.Now()
		m.Stop(2 * time.Second)
		if d := time.Since(started); d > 2*time.Second {
			t.Fatalf("Stop %s davom etdi", d)
		}
	})
}

type hangingReporter struct{}

func (hangingReporter) ReportUsage(ctx context.Context, _ []access.UsageWindow) (int, error) {
	<-ctx.Done()
	return 0, fmt.Errorf("%w: %v", access.ErrUnavailable, ctx.Err())
}

// Hisobot o'chiq: Reporter yo'q yoki oraliq 0 — nil Meter, uning barcha
// metodlari xavfsiz no-op.
func TestMeter_DisabledIsNilAndSafe(t *testing.T) {
	if m := New(Options{Interval: time.Minute}); m != nil {
		t.Fatal("Reporter'siz Meter yaratilmasligi kerak")
	}
	if m := New(Options{Reporter: &fakeReporter{}}); m != nil {
		t.Fatal("oraliq 0 da Meter yaratilmasligi kerak")
	}
	var m *Meter
	m.Start()
	closer := m.Open("t", "acme", (&fakeSource{}).usage)
	closer()
	m.Stop(time.Second)
}

func TestAlignDown(t *testing.T) {
	cases := []struct{ t, i, want int64 }{
		{0, 60, 0}, {59, 60, 0}, {60, 60, 60}, {61, 60, 60},
		{946684813, 60, 946684800}, {-1, 60, -60}, {7, 5, 5},
	}
	for _, c := range cases {
		if got := alignDown(c.t, c.i); got != c.want {
			t.Errorf("alignDown(%d, %d) = %d, %d kutilgan", c.t, c.i, got, c.want)
		}
	}
}
