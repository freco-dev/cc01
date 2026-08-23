// Package route yadrodagi overlay marshrutlarini peerlar ro'yxatiga
// moslab turadi.
//
// Nega alohida halqa kerak: marshrutlar `tun.Create` paytida bir marta
// qo'yiladi, peerlar esa doim o'zgaradi — node qo'shiladi, o'chadi,
// subnet e'lon qiladi. Bir marta qo'yilgan holat tez orada haqiqatdan
// uzoqlashadi va DEV_SPEC §8 talab qilgan "0 orphan marshrut" buziladi.
package route

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/freco-dev/cc01/daemon/router"
	"github.com/freco-dev/cc01/daemon/tun"
)

// DefaultInterval — davriy tekshiruv oralig'i.
//
// Rekonsiliatsiya asosan Poke bilan, ya'ni NetworkMap kelganda ishga
// tushadi. Taymer — ehtiyot chorasi: yadro holati bizdan so'ramasdan
// o'zgargan bo'lsa (interfeys tushib qolgan, boshqa jarayon aralashgan)
// shu yerda tuzatiladi.
const DefaultInterval = 30 * time.Second

// PeerSource — marshrutlar kimdan kelib chiqadi.
type PeerSource interface {
	Peers() []*router.Peer
}

// Sink — hisoblangan marshrutlar qayerga qo'yiladi.
type Sink interface {
	SetRoutes([]netip.Prefix) (tun.RouteDiff, error)
}

type Config struct {
	// Base — peerlardan qat'i nazar doim turadigan marshrutlar:
	// tenant /64. Busiz hali qo'shilmagan peerga yuborilgan paket
	// overlay'ga umuman tushmaydi.
	Base []netip.Prefix

	Peers PeerSource
	Sink  Sink

	// Interval — 0 bo'lsa DefaultInterval.
	Interval time.Duration

	Logger *slog.Logger
}

type Reconciler struct {
	cfg  Config
	poke chan struct{}

	mu     sync.Mutex
	last   []netip.Prefix
	synced bool
}

func New(cfg Config) *Reconciler {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Reconciler{
		cfg: cfg,
		// Bufer 1: Poke hech qachon bloklanmasligi kerak — uni
		// NetworkMap qayta ishlash yo'li chaqiradi va u sekinlashsa
		// butun CP oqimi to'xtaydi. Navbatda kutayotgan signal bo'lsa
		// yangisini tashlab yuboramiz: ikkalasi ham "qayta hisobla"
		// degani, ikki marta hisoblashning ma'nosi yo'q.
		poke: make(chan struct{}, 1),
	}
}

// Poke darhol rekonsiliatsiya so'raydi. Bloklanmaydi.
func (r *Reconciler) Poke() {
	select {
	case r.poke <- struct{}{}:
	default:
	}
}

// Run halqani yuritadi va ctx bekor qilinganda qaytadi.
func (r *Reconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	// Birinchi o'tish darhol: peerlar CP dan Run boshlanguncha ham
	// kelib ulgurgan bo'lishi mumkin.
	r.once()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.once()
		case <-r.poke:
			r.once()
		}
	}
}

// Once bitta rekonsiliatsiya bosqichini bajaradi va nima o'zgarganini
// qaytaradi. Testlar va `cc01 down` shuni chaqiradi.
func (r *Reconciler) Once() (tun.RouteDiff, error) {
	desired := r.desired()

	diff, err := r.cfg.Sink.SetRoutes(desired)

	r.mu.Lock()
	r.last = desired
	r.synced = err == nil
	r.mu.Unlock()

	return diff, err
}

func (r *Reconciler) once() {
	diff, err := r.Once()
	if err != nil {
		r.cfg.Logger.Warn("marshrutlarni moslashtirish", "err", err)
		return
	}
	if !diff.Empty() {
		r.cfg.Logger.Info("marshrutlar yangilandi", "diff", diff.String())
	}
}

// Desired — hozirgi holatda qanday marshrutlar bo'lishi kerak.
func (r *Reconciler) desired() []netip.Prefix {
	desired := slices.Clone(r.cfg.Base)

	if r.cfg.Peers != nil {
		for _, peer := range r.cfg.Peers.Peers() {
			for _, prefix := range peer.AllowedIPs() {
				// Tenant /64 ichidagi /128 lar uchun alohida marshrut
				// kerak emas — base prefiksi ularni allaqachon
				// qamrab olgan. Har bir peer uchun yozuv qo'shish
				// jadvalni node soniga chiziqli o'stiradi va hech
				// qanday marshrutlash qarorini o'zgartirmaydi.
				if covered(desired, prefix) {
					continue
				}
				desired = append(desired, prefix)
			}
		}
	}

	return desired
}

// Synced — oxirgi urinish muvaffaqiyatli tugadimi (`cc01 doctor` uchun).
func (r *Reconciler) Synced() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.synced
}

// Last — oxirgi hisoblangan marshrutlar to'plami.
func (r *Reconciler) Last() []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.last)
}

// covered — prefiks mavjudlaridan biri ichiga to'liq kiradimi.
func covered(existing []netip.Prefix, prefix netip.Prefix) bool {
	for _, outer := range existing {
		if outer.Bits() <= prefix.Bits() && outer.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
