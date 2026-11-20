// Package access core-server (Edge) va access-server (Account Plane)
// o'rtasidagi ichki kontraktni amalga oshiradi.
//
// Kontrakt: proto/cc01/v1/access.proto, ARCHITECTURE.md §3.4.3.
//
// Muhim invariant: access-server paket yo'lida EMAS. AuthorizeTunnel
// tunnel ochilayotganda (Authorize) va har bir ochiq tunnel uchun davriy
// ravishda — har ≤30 s (Renew, lease yangilanishi) — chaqiriladi; trafikning
// o'zi hech qachon AP'ga tegmaydi. AP yo'qligi (tarmoq xatosi, Unavailable,
// timeout) ochiq tunnelni hech qachon yopmaydi: tunnel oxirgi limitlar
// bilan ishlashda davom etadi (fail-static). Ochiq tunnelni faqat AP'ning
// aniq rad javobi (Denial) yopishi mumkin.
package access

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrUnavailable — access-server javob bermadi (tarmoq xatosi, Unavailable,
// timeout). Bu rad javobi EMAS: ochiq tunnel bunday xato tufayli yopilmaydi.
var ErrUnavailable = errors.New("access-server mavjud emas")

// Grant — avtorizatsiya muvaffaqiyatli tugagandagi natija.
//
// Grant o'zgarmas: Client uni keshda saqlaydi va bir nechta chaqiruvchiga
// bir xil ko'rsatkichni qaytaradi — chaqiruvchi maydonlarni o'zgartirmasligi
// shart.
type Grant struct {
	UserID    int64
	TenantID  string
	Plan      string
	Subdomain string

	MaxTunnels        int
	MaxConnsPerTunnel int
	BandwidthBps      uint64

	// LeaseTTL — natijani shu muddat davomida keshlash mumkin.
	LeaseTTL time.Duration

	// IssuedAt — AP'ga RPC BOSHLANGAN vaqt (javob kelgan vaqt emas). Faqat
	// Client o'rnatadi; kesh'dan qaytganda ham asl qiymati saqlanadi —
	// birinchi yangilanish shu vaqtga bog'lanadi. AllowAll uchun nol.
	IssuedAt time.Time
}

// Request — avtorizatsiya so'rovi.
type Request struct {
	Token        string
	Protocol     string
	Subdomain    string
	CustomDomain string
	CliVersion   string
	ClientIP     string

	// Renewal — ochiq tunnel lease yangilanishi: AP nom band qilmaydi va
	// kvota sanamaydi. Edge bunda BERILGAN subdomainni yuboradi.
	Renewal bool
}

// Denial — so'rov rad etildi. Bu tarmoq xatosi EMAS: server javob berdi
// va "yo'q" dedi. Chaqiruvchi ikkalasini ajratishi kerak, chunki fail-static
// faqat tarmoq xatosiga taalluqli.
type Denial struct {
	Code    string
	Message string
}

func (d *Denial) Error() string {
	return fmt.Sprintf("%s: %s", d.Code, d.Message)
}

// Authorizer — tunnel so'rovini avtorizatsiya qiluvchi.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (*Grant, error)
	Close() error
}

// Renewer — ochiq tunnel ruxsatini qayta tekshiruvchi (ixtiyoriy interfeys).
//
// Renew hech qachon keshdagi natijani qaytarmaydi: har chaqiruv AP'ga
// boradi. AP javob bermasa — ErrUnavailable'ni o'rab olgan xato (Denial
// emas) qaytadi va chaqiruvchi oxirgi limitlarni saqlab qoladi.
//
// AllowAll bu interfeysni ataylab amalga oshirmaydi: avtorizatsiya
// o'chirilgan rejimda yangilash ma'nosiz.
type Renewer interface {
	Renew(ctx context.Context, req Request) (*Grant, error)
}

// UsageWindow — bitta tunnelning bitta vaqt oynasidagi foydalanishi
// (proto: cc01.v1.UsageWindow). AP uni (TunnelID, WindowStart) bo'yicha
// idempotent saqlaydi, shuning uchun TunnelID har tunnel NUSXASI uchun
// noyob bo'lishi shart.
type UsageWindow struct {
	TenantID    string // tenant slug (Grant.TenantID)
	TunnelID    string
	WindowStart int64 // unix sekund, oyna boshi (ichiga kiradi)
	WindowEnd   int64 // unix sekund, oyna oxiri (kirmaydi); > WindowStart
	BytesIn     uint64
	BytesOut    uint64
	Connections uint32
	Rejected    uint32
}

// UsageReporter — foydalanish oynalarini AP'ga yuboruvchi (ixtiyoriy
// interfeys, Renewer kabi).
//
// accepted — AP qabul qilgan oynalar soni (0..len(windows)): chaqiruvchi
// navbat boshidan shuncha oynani o'chiradi, qolganini qayta yuboradi.
// Xato (AP yo'q, Unavailable, taymaut) — ErrUnavailable'ni o'rab oladi;
// bunda hech bir oyna qabul qilinmagan deb hisoblanadi.
//
// AllowAll bu interfeysni ataylab amalga oshirmaydi: avtorizatsiya
// o'chirilgan rejimda hisobot qabul qiladigan AP yo'q.
type UsageReporter interface {
	ReportUsage(ctx context.Context, windows []UsageWindow) (accepted int, err error)
}

// AllowAll — avtorizatsiya o'chirilgan rejim (CC01_AUTH_MODE=disabled).
//
// Faqat lokal ishlab chiqish va sinov uchun. Har qanday token qabul
// qilinadi va subdomain egaligi tekshirilmaydi — ya'ni "birinchi kelgan
// oladi" mantiqiga qaytamiz. Prod'da ishlatilmaydi; server ishga
// tushganda bu haqda ogohlantirish chiqaradi.
type AllowAll struct {
	Limits Grant
}

func (a *AllowAll) Authorize(_ context.Context, req Request) (*Grant, error) {
	grant := a.Limits
	grant.Subdomain = req.Subdomain
	return &grant, nil
}

func (a *AllowAll) Close() error { return nil }
