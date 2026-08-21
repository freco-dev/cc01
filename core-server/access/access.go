// Package access core-server (Edge) va access-server (Account Plane)
// o'rtasidagi ichki kontraktni amalga oshiradi.
//
// Kontrakt: proto/cc01/v1/access.proto, ARCHITECTURE.md §3.4.3.
//
// Muhim invariant: bu paket faqat tunnel OCHILAYOTGANDA chaqiriladi.
// Ochilgandan keyin trafik access-server'ga tegmaydi — ya'ni AP yiqilsa
// oqayotgan tunnellar ishlashda davom etadi.
package access

import (
	"context"
	"fmt"
	"time"
)

// Grant — avtorizatsiya muvaffaqiyatli tugagandagi natija.
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
}

// Request — avtorizatsiya so'rovi.
type Request struct {
	Token        string
	Protocol     string
	Subdomain    string
	CustomDomain string
	CliVersion   string
	ClientIP     string
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
