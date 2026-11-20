package main

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/freco-dev/cc01/core-server/access"
	"github.com/freco-dev/cc01/core-server/config"
)

// renewRetryCap — AP javob bermaganda qayta urinishlar orasidagi eng
// katta pauza. Yangilash oralig'i undan qisqa bo'lsa, o'shanisi olinadi.
const renewRetryCap = 10 * time.Second

// limitSink — ochiq tunnelning jonli o'zgartiriladigan limitlari.
type limitSink interface {
	SetMaxConns(n int)
	MaxConns() int
}

// superviseTunnel ochiq tunnel ruxsatini AP'da davriy qayta tekshiradi
// (lease yangilanishi) va yangi limitlarni tunnelga qo'llaydi.
//
// Klient ketguncha (clientGone) yoki ctx bekor bo'lguncha ishlaydi va nil
// qaytaradi. Tunnelni faqat allowlist'dagi aniq rad javobi yopadi: shunda
// notify chaqiriladi va o'sha rad javobi qaytariladi — chaqiruvchi tunnelni
// yopadi.
//
// Kafolat (DEV_SPEC §8): AP'dagi o'zgarish ≤ R + taymaut ichida qo'llanadi
// (edge→AP kanali tayyor bo'lganda; AP yiqilib qaytgandan keyin kanal
// qayta ulanguncha yana ≤ config.AccessReconnectMax qo'shiladi). Config bu
// yig'indini 60 s dan kichik bo'lishga majbur qiladi.
//   - Birinchi yangilash grant.IssuedAt'ga (RPC boshlangan vaqtga)
//     bog'langan: tunnel keshdagi eski natija bilan ochilgan bo'lsa ham,
//     yangilash kechikmaydi. Keshdagi natija esa ko'pi bilan R yangi
//     hisoblanadi (access.Client: min(MaxFresh, LeaseTTL/2)).
//   - Har keyingi yangilash ham oldingisining IssuedAt'idan hisoblanadi va
//     jitter faqat KAMAYTIRADI (R·U[0.8,1]) — oraliq hech qachon R dan
//     oshmaydi.
//
// Fail-static: AP javob bermasa (ErrUnavailable) tunnel oxirgi limitlar
// bilan muddatsiz ishlaydi va min(R, 10 s)·jitter dan keyin qayta uriniladi.
func (j *CC01Server) superviseTunnel(
	ctx context.Context,
	t limitSink,
	notify func(code, msg string) error,
	req access.Request,
	g *access.Grant,
	id string,
	clientGone <-chan struct{},
) (denial *access.Denial) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Klient ketsa davom etayotgan RPC ham bekor qilinadi — tunnel
	// tozalanishi AP taymautini kutib qolmaydi.
	go func() {
		select {
		case <-clientGone:
			cancel()
		case <-ctx.Done():
		}
	}()

	renewer, ok := j.authorizer.(access.Renewer)
	r := renewInterval(j.config.AccessRenew, g.LeaseTTL)
	if !ok || r <= 0 {
		<-ctx.Done()
		return nil
	}

	// Edge BERILGAN nomni yuboradi: klient bo'sh qoldirgan bo'lsa ham AP
	// aynan shu tunnel egallagan nomni tekshirishi kerak.
	req.Subdomain = g.Subdomain
	req.Renewal = true

	plan := g.Plan
	timer := time.NewTimer(renewDelay(g.IssuedAt, time.Now(), r))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}

		grant, err := renewer.Renew(ctx, req)
		if ctx.Err() != nil {
			// Klient ketdi: natija endi ahamiyatsiz.
			return nil
		}

		var next time.Duration
		var denied *access.Denial
		switch {
		case err == nil:
			if n := j.effectiveMaxConns(grant); n != t.MaxConns() || grant.Plan != plan {
				t.SetMaxConns(n)
				plan = grant.Plan
				j.logf("[tunnel-limits] %s plan=%s max_conns=%d", id, grant.Plan, n)
			}
			next = renewDelay(grant.IssuedAt, time.Now(), r)

		case errors.As(err, &denied):
			next = jitter(r)
			if !closesTunnel(denied.Code) {
				// Noma'lum yoki vaqtinchalik kod — buggy AP hamma
				// tunnellarni yopib yubormasligi uchun tunnel saqlanadi.
				j.logf("[tunnel-renew-failed] %s code=%s err=%s (tunnel saqlanadi)",
					id, denied.Code, denied.Message)
				break
			}
			if j.config.AccessRenewDeny == config.RenewDenyLog {
				j.logf("[tunnel-revoke-dryrun] %s code=%s", id, denied.Code)
				break
			}
			j.logf("[tunnel-revoked] %s code=%s", id, denied.Code)
			if err := notify(denied.Code, denied.Message); err != nil {
				j.logf("[tunnel-revoked] %s bildirishnoma yuborilmadi: %v", id, err)
			}
			return denied

		default:
			// AP javob bermadi: oxirgi limitlar saqlanadi (fail-static).
			// Xato matnida token yo'q — u faqat so'rovda ketadi.
			j.logf("[tunnel-renew-failed] %s err=%v", id, err)
			next = jitter(min(r, renewRetryCap))
		}

		timer.Reset(next)
	}
}

// renewInterval yangilash oralig'i R = min(sozlama, LeaseTTL/2).
// 0 — yangilash o'chirilgan.
func renewInterval(cfg, leaseTTL time.Duration) time.Duration {
	if cfg <= 0 {
		return 0
	}
	if half := leaseTTL / 2; half > 0 && half < cfg {
		return half
	}
	return cfg
}

// renewDelay keyingi yangilashgacha kutish: issuedAt + R·U[0.8,1] − now,
// manfiy bo'lsa 0. issuedAt nol bo'lsa (AP vaqtni bermagan) — now dan.
//
// Keshdan ochilgan va allaqachon R yoshidagi grant uchun natija 0:
// tunnel darhol yangilanadi.
func renewDelay(issuedAt, now time.Time, r time.Duration) time.Duration {
	if issuedAt.IsZero() {
		issuedAt = now
	}
	return max(0, issuedAt.Add(jitter(r)).Sub(now))
}

// jitter d ni [0.8·d, d] oralig'idagi tasodifiy qiymatga almashtiradi.
// Faqat kamaytiradi — 60 s kafolati jitter tufayli buzilmaydi; AP
// tiklanganda yangilashlar bir lahzaga to'planib qolmaydi.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	low := d - d/5
	return low + rand.N(d-low+1)
}

// closesTunnel — bu rad javobi ochiq tunnelni yopadimi.
//
// Ataylab allowlist: noma'lum, UNSPECIFIED yoki vaqtinchalik kodlar
// (SUBDOMAIN_BUSY, QUOTA_*) tunnelni yopmaydi — AP'dagi xato hamma ochiq
// tunnellarni bir zumda o'chirib yubormasligi kerak.
func closesTunnel(code string) bool {
	switch code {
	case "TOKEN_INVALID", "TOKEN_REVOKED", "TOKEN_EXPIRED",
		"PLAN_SUSPENDED", "SUBDOMAIN_NOT_OWNED":
		return true
	default:
		return false
	}
}
