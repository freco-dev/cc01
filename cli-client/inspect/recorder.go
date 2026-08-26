// Package inspect tunnel orqali o'tgan HTTP trafigini kuzatadi
// (DEV_SPEC §5.1, Faza 3).
//
// ⚠️ Kuzatuv PASSIV: baytlar `io.TeeReader` orqali nusxalanadi va
// oqimning o'zi hech qachon o'zgartirilmaydi. Parser yiqilsa ham
// tunnel ishlashda davom etadi — inspector qulaylik vositasi,
// ma'lumot yo'lining bir qismi emas.
package inspect

import (
	"net/http"
	"sync"
	"time"
)

// DefaultBodyLimit — saqlanadigan tananing chegarasi.
//
// Chegara kerak: inspector xotirada ishlaydi va katta fayl
// yuklash butun jarayonni yeb qo'yardi.
const DefaultBodyLimit = 64 << 10

// DefaultCapacity — saqlanadigan almashuvlar soni.
const DefaultCapacity = 200

// Exchange — bitta so'rov/javob jufti.
type Exchange struct {
	ID      int       `json:"id"`
	Started time.Time `json:"started"`

	Method string `json:"method"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Proto  string `json:"proto"`

	RequestHeaders http.Header `json:"request_headers"`
	RequestBody    string      `json:"request_body"`

	// RequestTruncated — tana chegaradan oshgani uchun qirqilgan.
	RequestTruncated bool `json:"request_truncated"`

	Status          int         `json:"status"`
	ResponseHeaders http.Header `json:"response_headers"`
	ResponseBody    string      `json:"response_body"`

	ResponseTruncated bool `json:"response_truncated"`

	// DurationMS — so'rov o'qilganidan javob o'qilgunga qadar.
	DurationMS int64 `json:"duration_ms"`

	// Error — javobni o'qishda xato bo'lsa (masalan ulanish
	// uzilgan). Bo'sh bo'lsa almashuv to'liq.
	Error string `json:"error,omitempty"`
}

// Recorder almashuvlarni saqlaydi va obunachilarga uzatadi.
type Recorder struct {
	capacity  int
	bodyLimit int

	mu        sync.RWMutex
	exchanges []Exchange
	nextID    int

	// subscribers — jonli oqim uchun. Kanal TO'LGAN bo'lsa yozuv
	// TASHLAB YUBORILADI: sekin obunachi tufayli tunnel
	// sekinlashmasligi kerak.
	subscribers map[int]chan Exchange
	nextSub     int
}

// Options — recorder sozlamalari.
type Options struct {
	// Capacity — xotirada saqlanadigan almashuvlar soni.
	// 0 bo'lsa DefaultCapacity.
	Capacity int

	// BodyLimit — saqlanadigan tananing chegarasi baytlarda.
	// 0 bo'lsa DefaultBodyLimit.
	BodyLimit int
}

func New(opts Options) *Recorder {
	capacity := opts.Capacity
	if capacity <= 0 {
		capacity = DefaultCapacity
	}

	limit := opts.BodyLimit
	if limit <= 0 {
		limit = DefaultBodyLimit
	}

	return &Recorder{
		capacity:    capacity,
		bodyLimit:   limit,
		subscribers: make(map[int]chan Exchange),
	}
}

// BodyLimit — saqlanadigan tananing chegarasi.
func (r *Recorder) BodyLimit() int { return r.bodyLimit }

// record almashuvni saqlaydi va obunachilarga yuboradi.
func (r *Recorder) record(exchange Exchange) {
	r.mu.Lock()
	r.nextID++
	exchange.ID = r.nextID

	r.exchanges = append(r.exchanges, exchange)
	if len(r.exchanges) > r.capacity {
		// Eng eskisini tashlaymiz. Nusxa ko'chirish o'rniga
		// kesib qo'ysak, massiv ostidagi xotira o'sib borardi.
		copy(r.exchanges, r.exchanges[len(r.exchanges)-r.capacity:])
		r.exchanges = r.exchanges[:r.capacity]
	}

	subscribers := make([]chan Exchange, 0, len(r.subscribers))
	for _, ch := range r.subscribers {
		subscribers = append(subscribers, ch)
	}
	r.mu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- exchange:
		default:
			// Sekin obunachi — o'tkazib yuboramiz.
		}
	}
}

// Exchanges — saqlangan almashuvlar, eng yangisi oxirida.
func (r *Recorder) Exchanges() []Exchange {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Exchange, len(r.exchanges))
	copy(out, r.exchanges)
	return out
}

// Subscribe jonli oqimga obuna bo'ladi.
//
// Qaytgan funksiya obunani bekor qiladi va uni CHAQIRISH SHART:
// aks holda har bir yopilgan brauzer sahifasi kanalni qoldirib
// ketardi.
func (r *Recorder) Subscribe() (<-chan Exchange, func()) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nextSub++
	id := r.nextSub

	// Buferli: `record` bloklanmasligi kerak.
	ch := make(chan Exchange, 16)
	r.subscribers[id] = ch

	return ch, func() {
		r.mu.Lock()
		defer r.mu.Unlock()

		if existing, ok := r.subscribers[id]; ok {
			delete(r.subscribers, id)
			close(existing)
		}
	}
}

// Clear saqlanganlarni tozalaydi.
func (r *Recorder) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exchanges = nil
}
