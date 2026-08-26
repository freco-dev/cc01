package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Device — sozlangan TUN interfeysi.
//
// O'qish/yozish `wireguard/tun` ga o'tkaziladi: u har bir platformada
// batch I/O ni (Linux'da `readv`/`writev`, GSO/GRO) allaqachon to'g'ri
// bajaradi.
type Device struct {
	inner wgtun.Device
	cfg   Config
	name  string

	// configured — manzil/marshrut qo'yilganmi. Close() faqat o'zi
	// qo'ygan narsalarni tozalaydi.
	configured bool

	// applied — oxirgi marta qo'llangan marshrutlar. Yadrodan o'qib
	// bo'lmaydigan platformalarda (macOS) rekonsiliatsiya shunga
	// tayanadi.
	routesMx sync.Mutex
	applied  []netip.Prefix

	closeOnce sync.Once
	closeErr  error
}

// Create TUN qurilmasini yaratadi, ko'taradi va sozlaydi.
//
// Har qanday bosqichda xato bo'lsa, shu paytgacha qilinganlar bekor
// qilinadi — yarim sozlangan interfeys qolib ketmaydi.
func Create(cfg Config) (*Device, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()

	inner, err := wgtun.CreateTUN(cfg.Name, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("tun: qurilma yaratish (%s): %w", cfg.Name, err)
	}

	// Yadro nomni o'zgartirishi mumkin (masalan macOS'da utun0, utun1…),
	// shuning uchun haqiqiy nomni undan so'raymiz.
	name, err := inner.Name()
	if err != nil {
		_ = inner.Close()
		return nil, fmt.Errorf("tun: nomni olish: %w", err)
	}

	device := &Device{inner: inner, cfg: cfg, name: name}

	if err := configure(name, cfg); err != nil {
		_ = cleanup(name)
		_ = inner.Close()
		return nil, err
	}
	device.configured = true

	// Create qo'ygan marshrutlarni boshlang'ich holat sifatida eslab
	// qolamiz, shunda birinchi SetRoutes ularni "yangi" deb hisoblamaydi.
	if normalized, err := normalizeRoutes(cfg.Routes); err == nil {
		device.applied = normalized
	}

	return device, nil
}

// Name — interfeysning haqiqiy nomi (yadro bergani).
func (d *Device) Name() string { return d.name }

// MTU — interfeys MTU'si.
func (d *Device) MTU() (int, error) { return d.inner.MTU() }

// BatchSize — bitta chaqiruvda o'qish/yozish mumkin bo'lgan paketlar soni.
func (d *Device) BatchSize() int { return d.inner.BatchSize() }

// ErrOffsetTooSmall — bufer boshida yetarli headroom qoldirilmagan.
var ErrOffsetTooSmall = errors.New("tun: offset Offset dan kichik")

// Read bir yoki bir nechta paketni o'qiydi. Har bir paket `bufs[i]` ning
// `offset` pozitsiyasidan boshlab yoziladi, uzunligi `sizes[i]` ga.
//
// `offset` kamida Offset bo'lishi SHART — sababi Offset izohida.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < Offset {
		return 0, fmt.Errorf("%w: %d < %d", ErrOffsetTooSmall, offset, Offset)
	}
	return d.inner.Read(bufs, sizes, offset)
}

// Write bir yoki bir nechta paketni yozadi. Har bir paket `bufs[i]` ning
// `offset` pozitsiyasidan boshlanadi.
//
// `offset` kamida Offset bo'lishi SHART. Aks holda platforma o'z
// sarlavhasini yozishga joy topa olmaydi va `invalid offset` qaytaradi —
// bu xatoni bu yerda, tushunarli xabar bilan ushlaymiz.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	if offset < Offset {
		return 0, fmt.Errorf("%w: %d < %d", ErrOffsetTooSmall, offset, Offset)
	}
	return d.inner.Write(bufs, offset)
}

// NewBuffers datapath uchun to'g'ri o'lchamdagi buferlar yaratadi:
// headroom + MTU + AEAD tegi uchun joy.
func (d *Device) NewBuffers() ([][]byte, []int) {
	size := d.BatchSize()

	bufs := make([][]byte, size)
	for i := range bufs {
		bufs[i] = make([]byte, Offset+d.cfg.MTU+64)
	}
	return bufs, make([]int, size)
}

// Events — qurilma hodisalari (MTU o'zgarishi, up/down).
func (d *Device) Events() <-chan wgtun.Event { return d.inner.Events() }

// Close interfeysni yopadi va biz qo'shgan manzil/marshrutlarni tozalaydi.
//
// Foydalanuvchining o'z marshrutlariga TEGILMAYDI: biz faqat ajratilgan
// jadvaldagi (RouteTable) yozuvlarni o'chiramiz.
// Close bir necha marta chaqirilishi mumkin — birinchi natija
// eslab qolinadi. Bu kerak, chunki qurilmani engine ham, uni yaratgan
// kod ham yopishi mumkin.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		var cleanupErr error
		if d.configured {
			cleanupErr = cleanup(d.name)
		}

		closeErr := d.inner.Close()

		// Qurilmani yopish muhimroq — uning xatosini birinchi qaytaramiz.
		if closeErr != nil {
			d.closeErr = fmt.Errorf("tun: qurilmani yopish: %w", closeErr)
			return
		}
		d.closeErr = cleanupErr
	})
	return d.closeErr
}
