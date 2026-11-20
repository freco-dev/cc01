// Package usage ochiq tunnellarning foydalanishini (trafik, ulanishlar)
// vaqt oynalariga bo'lib, access-server'ga (AP) yuboradi
// (DEV_SPEC §8 "ReportUsage + UsageRecord").
//
// Oqim:
//
//	tunnel (atomik hisoblagichlar) → Meter.Open … closer()
//	   ↓ har oraliq chegarasida (devor soatiga tekislangan) va yopilishda
//	oyna → xotiradagi navbat (≤ QueueMax) → ReportUsage (≤ BatchMax) → AP
//
// Kafolatlar:
//   - Har ochiq tunnel uchun har oraliqda oyna kesiladi — trafiksiz
//     tunnel uchun ham (AP tunnel-soatlarni oyna davomiyligidan oladi).
//   - Bitta tunnelning oynalari ustma-ust tushmaydi va bo'sh emas
//     (WindowEnd > WindowStart), unix sekund aniqligida.
//   - AP yo'qligi tunnellarga ta'sir qilmaydi: oynalar navbatda qoladi va
//     keyingi tikda qayta yuboriladi. Navbat to'lsa ENG ESKISI tashlanadi.
//   - Edge qulasa navbat yo'qoladi (ko'pi bilan bir marta yetkazish).
package usage

import (
	"context"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/freco-dev/cc01/core-server/access"
	"github.com/freco-dev/cc01/core-server/tunnel"
)

const (
	// DefaultQueueMax — xotiradagi navbatning eng ko'p oynalari soni.
	DefaultQueueMax = 10_000
	// DefaultBatchMax — bitta ReportUsage chaqiruvidagi eng ko'p oynalar.
	DefaultBatchMax = 500
)

// Options — Meter sozlamalari.
type Options struct {
	// Reporter — oynalarni qabul qiluvchi (access.Client). nil — hisobot
	// o'chiq (New nil qaytaradi).
	Reporter access.UsageReporter
	// Interval — oyna uzunligi va yuborish oralig'i; butun sekund
	// bo'lishi kerak. <= 0 — hisobot o'chiq (New nil qaytaradi).
	Interval time.Duration
	// Logf — log yozuvchisi (token hech qachon uzatilmaydi). nil — jim.
	Logf func(format string, args ...any)

	// QueueMax va BatchMax — 0 bo'lsa Default* ishlatiladi.
	QueueMax int
	BatchMax int
}

// Meter ochiq tunnellarni o'lchaydi va oynalarni AP'ga yuboradi.
//
// nil *Meter — hisobot o'chiq: Open no-op yopuvchi qaytaradi, Start va
// Stop hech narsa qilmaydi.
type Meter struct {
	reporter access.UsageReporter
	interval int64 // sekund
	logf     func(format string, args ...any)
	queueMax int
	batchMax int

	mu       sync.Mutex
	tunnels  map[*metered]struct{} // mu ostida
	openSeq  uint64                // mu ostida: tunnellar tartibi
	queue    []queued              // mu ostida: seq bo'yicha uzluksiz, o'suvchi
	nextSeq  uint64                // mu ostida
	stopped  bool                  // mu ostida
	cancel   context.CancelFunc
	finished chan struct{}
}

type queued struct {
	seq uint64
	w   access.UsageWindow
}

// metered — bitta ochiq tunnelning o'lchov holati (Meter.mu ostida).
type metered struct {
	order   uint64
	id      string
	tenant  string
	source  func() tunnel.Usage
	lastEnd int64        // oxirgi kesilgan oyna oxiri (unix s); keyingisining boshi
	prev    tunnel.Usage // lastEnd paytidagi kumulyativ qiymatlar
}

// New Meter yaratadi. Reporter nil yoki Interval <= 0 bo'lsa nil
// qaytaradi (hisobot o'chiq).
func New(opts Options) *Meter {
	if opts.Reporter == nil || opts.Interval <= 0 {
		return nil
	}
	interval := int64(opts.Interval / time.Second)
	if interval < 1 {
		interval = 1
	}
	m := &Meter{
		reporter: opts.Reporter,
		interval: interval,
		logf:     opts.Logf,
		queueMax: opts.QueueMax,
		batchMax: opts.BatchMax,
		tunnels:  make(map[*metered]struct{}),
	}
	if m.logf == nil {
		m.logf = func(string, ...any) {}
	}
	if m.queueMax <= 0 {
		m.queueMax = DefaultQueueMax
	}
	if m.batchMax <= 0 {
		m.batchMax = DefaultBatchMax
	}
	return m
}

// Open tunnelni o'lchashga qo'yadi va uni yopuvchi funksiyani qaytaradi.
//
// id — tunnel NUSXASI uchun noyob (AP oynalarni (id, window_start)
// bo'yicha saqlaydi), tenant — tenant slug (Grant.TenantID), source —
// tunnelning kumulyativ hisoblagichlari (tunnel.Tunnel.Usage). Birinchi
// oyna hozirgi sekunddan boshlanadi; hisoblagichlar noldan olinadi.
//
// Qaytgan funksiya yakuniy (qisman) oynani yopilish vaqtigacha kesadi;
// uni tunnel yopilgandan KEYIN chaqirish kerak (oxirgi baytlar ham
// hisoblansin). Qayta chaqirish xavfsiz.
func (m *Meter) Open(id, tenant string, source func() tunnel.Usage) (closer func()) {
	if m == nil {
		return func() {}
	}

	now := time.Now()
	mt := &metered{
		id:      id,
		tenant:  tenant,
		source:  source,
		lastEnd: now.Unix(),
	}

	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return func() {}
	}
	m.openSeq++
	mt.order = m.openSeq
	m.tunnels[mt] = struct{}{}
	m.mu.Unlock()

	var once sync.Once
	return func() { once.Do(func() { m.close(mt, time.Now()) }) }
}

// close tunnelning yakuniy oynasini [lastEnd, yopilish) kesadi.
//
// Yopilish sekundga pastga yaxlitlanadi. U lastEnd bilan bir sekundga
// tushsa (tunnel shu sekundda ochilgan yoki oxirgi chegaradan < 1 s
// o'tgan), oyna 1 s ga cho'ziladi: [lastEnd, lastEnd+1) — aks holda
// oxirgi baytlar va ulanishlar yo'qolardi. Bu oyna keyingi chegaradan
// oshmaydi (oraliq ≥ 5 s).
func (m *Meter) close(mt *metered, at time.Time) {
	m.mu.Lock()
	if _, ok := m.tunnels[mt]; !ok || m.stopped {
		m.mu.Unlock()
		return
	}
	delete(m.tunnels, mt)
	w := mt.cut(max(at.Unix(), mt.lastEnd+1))
	dropped := m.enqueueLocked(w)
	m.mu.Unlock()

	m.logDropped(dropped)
}

// Start hisobot goroutine'ini ishga tushiradi: har tekislangan chegarada
// barcha ochiq tunnellar uchun oyna kesadi va navbatni yuboradi.
func (m *Meter) Start() {
	if m == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancel = cancel
	m.finished = make(chan struct{})
	m.mu.Unlock()
	go func() {
		defer close(m.finished)
		m.run(ctx)
	}()
}

// Stop hisobot goroutine'ini to'xtatadi, hali ochiq tunnellar uchun
// yakuniy oynalarni hozirgacha kesadi va navbatni flushTimeout ichida
// best-effort yuboradi. Shundan keyin Meter hech narsani o'lchamaydi.
func (m *Meter) Stop(flushTimeout time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	cancel, finished := m.cancel, m.finished
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		<-finished
	}

	now := time.Now()
	m.mu.Lock()
	var windows []access.UsageWindow
	for _, mt := range m.sortedLocked() {
		windows = append(windows, mt.cut(max(now.Unix(), mt.lastEnd+1)))
		delete(m.tunnels, mt)
	}
	dropped := m.enqueueLocked(windows...)
	m.stopped = true
	m.mu.Unlock()
	m.logDropped(dropped)

	ctx, cancelFlush := context.WithTimeout(context.Background(), flushTimeout)
	defer cancelFlush()
	m.flush(ctx)
}

// run har tekislangan chegarada (unix vaqt interval'ga karrali) tick
// chaqiradi. Kechikkan tik (masalan, uyqudan keyin) oxirgi o'tgan
// chegaragacha bitta uzunroq oyna kesadi — oynalar baribir ustma-ust
// tushmaydi.
func (m *Meter) run(ctx context.Context) {
	for {
		now := time.Now()
		next := alignDown(now.Unix(), m.interval) + m.interval
		timer := time.NewTimer(time.Unix(next, 0).Sub(now))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		m.tick(ctx, time.Now())
	}
}

// tick bitta chegara: oynalarni kesadi va navbatni yuboradi.
func (m *Meter) tick(ctx context.Context, now time.Time) {
	m.cutAll(alignDown(now.Unix(), m.interval))
	m.flush(ctx)
}

// cutAll har ochiq tunnel uchun [lastEnd, boundary) oynasini kesadi.
// boundary <= lastEnd bo'lsa (tunnel shu chegara sekundida ochilgan yoki
// soat orqaga ketgan) oyna kesilmaydi: trafik keyingi oynaga qo'shiladi.
func (m *Meter) cutAll(boundary int64) {
	m.mu.Lock()
	var windows []access.UsageWindow
	for _, mt := range m.sortedLocked() {
		if boundary > mt.lastEnd {
			windows = append(windows, mt.cut(boundary))
		}
	}
	dropped := m.enqueueLocked(windows...)
	m.mu.Unlock()
	m.logDropped(dropped)
}

// flush navbatni BatchMax lik bo'laklarda yuboradi. Xato yoki to'liq
// qabul qilinmagan bo'lak sikldan chiqaradi — qolgani keyingi tikda.
func (m *Meter) flush(ctx context.Context) {
	sent, accepted := 0, 0
	defer func() {
		if sent > 0 {
			m.logf("[usage-reported] windows=%d accepted=%d", sent, accepted)
		}
	}()

	for ctx.Err() == nil {
		m.mu.Lock()
		n := min(len(m.queue), m.batchMax)
		if n == 0 {
			m.mu.Unlock()
			return
		}
		first := m.queue[0].seq
		batch := make([]access.UsageWindow, n)
		for i := range batch {
			batch[i] = m.queue[i].w
		}
		m.mu.Unlock()

		got, err := m.reporter.ReportUsage(ctx, batch)
		if err != nil {
			m.mu.Lock()
			left := len(m.queue)
			m.mu.Unlock()
			m.logf("[usage-report-failed] queued=%d err=%v", left, err)
			return
		}
		got = max(0, min(got, n))
		sent += n
		accepted += got

		// Yuborish paytida eng eskilari tashlangan bo'lishi mumkin —
		// shuning uchun indeks emas, seq bo'yicha o'chiriladi.
		m.mu.Lock()
		upto := first + uint64(got)
		i := 0
		for i < len(m.queue) && m.queue[i].seq < upto {
			i++
		}
		m.queue = slices.Delete(m.queue, 0, i)
		m.mu.Unlock()

		if got < n {
			return
		}
	}
}

// enqueueLocked oynalarni navbat oxiriga qo'shadi; to'lib ketsa eng
// eskilarini tashlaydi va ularning sonini qaytaradi. m.mu ostida.
func (m *Meter) enqueueLocked(windows ...access.UsageWindow) (dropped int) {
	for _, w := range windows {
		m.queue = append(m.queue, queued{seq: m.nextSeq, w: w})
		m.nextSeq++
	}
	if over := len(m.queue) - m.queueMax; over > 0 {
		m.queue = slices.Delete(m.queue, 0, over)
		dropped = over
	}
	return dropped
}

func (m *Meter) logDropped(n int) {
	if n > 0 {
		m.logf("[usage-dropped] n=%d (navbat to'la)", n)
	}
}

// sortedLocked ochiq tunnellarni ochilish tartibida qaytaradi. m.mu ostida.
func (m *Meter) sortedLocked() []*metered {
	list := make([]*metered, 0, len(m.tunnels))
	for mt := range m.tunnels {
		list = append(list, mt)
	}
	slices.SortFunc(list, func(a, b *metered) int {
		switch {
		case a.order < b.order:
			return -1
		case a.order > b.order:
			return 1
		default:
			return 0
		}
	})
	return list
}

// cut [lastEnd, end) oynasini quradi va holatni oldinga suradi.
// Chaqiruvchi end > lastEnd ni ta'minlaydi.
func (mt *metered) cut(end int64) access.UsageWindow {
	cur := mt.source()
	w := access.UsageWindow{
		TenantID:    mt.tenant,
		TunnelID:    mt.id,
		WindowStart: mt.lastEnd,
		WindowEnd:   end,
		BytesIn:     delta(cur.BytesIn, mt.prev.BytesIn),
		BytesOut:    delta(cur.BytesOut, mt.prev.BytesOut),
		Connections: clamp32(delta(cur.Connections, mt.prev.Connections)),
		Rejected:    clamp32(delta(cur.Rejected, mt.prev.Rejected)),
	}
	mt.prev = cur
	mt.lastEnd = end
	return w
}

// alignDown — t dan oshmaydigan, interval ga karrali eng katta unix sekund.
func alignDown(t, interval int64) int64 {
	r := t % interval
	if r < 0 {
		r += interval
	}
	return t - r
}

func delta(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func clamp32(v uint64) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}
