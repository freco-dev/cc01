package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

// Client — access-server'ga gRPC klienti, kesh va fail-static bilan.
type Client struct {
	conn    *grpc.ClientConn
	service cc01v1.AccessInternalServiceClient
	timeout time.Duration

	// grace — access-server yo'q bo'lganda kesh'dagi natija qancha vaqt
	// yaroqli hisoblanishi (ARCHITECTURE.md §3.4.3).
	grace time.Duration

	// maxFresh — yangilash oralig'i sozlamasi (CC01_ACCESS_RENEW). Kesh
	// yangiligi R = min(maxFresh, LeaseTTL/2) bilan cheklanadi (0 — chegara
	// yo'q, LeaseTTL ishlatiladi).
	maxFresh time.Duration

	mu sync.Mutex
	// cache token hashi bo'yicha guruhlangan: rad javobi bitta tokenning
	// barcha tegishli yozuvlarini to'liq ko'rib chiqmasdan o'chira oladi.
	cache     map[string]*tokenCache
	lastSweep time.Time
}

// cacheKey — kesh kaliti. Tokenning o'zi emas, uning hashi saqlanadi — xom
// token xotiradagi map kalitlarida qolib ketmasligi uchun.
type cacheKey struct {
	token        string
	subdomain    string
	customDomain string
}

type cacheEntry struct {
	grant     *Grant
	freshFor  time.Time // shu vaqtgacha qayta so'ramaymiz (IssuedAt'dan hisoblanadi)
	usableFor time.Time // AP yiqilsa shu vaqtgacha ishlatiladi (IssuedAt'dan hisoblanadi)
}

// tokenCache — bitta tokenning kesh yozuvlari va rad javoblari izi.
//
// Iz (tombstone) — rad javobi berilgan RPC BOSHLANGAN vaqt. Undan oldin
// boshlangan RPC'ning grant'i (javobi kechroq kelgan bo'lsa ham) keshga
// yozilmaydi: aks holda bekor qilingan token keshda qayta tirilardi.
type tokenCache struct {
	entries map[cacheKey]cacheEntry

	deniedAt       time.Time            // butun token rad etilgan (TOKEN_*, PLAN_SUSPENDED, …)
	subDeniedAt    map[string]time.Time // shu subdomain uchun rad etilgan
	domainDeniedAt map[string]time.Time // shu custom domain uchun rad etilgan
}

// Options — klient sozlamalari.
type Options struct {
	Address string
	Timeout time.Duration
	Grace   time.Duration

	// MaxFresh — yangilash oralig'i sozlamasi (CC01_ACCESS_RENEW). Kesh
	// yangiligi edge'dagi yangilash oralig'iga R = min(MaxFresh, LeaseTTL/2)
	// tenglanadi: aks holda keshdan ochilgan tunnel AP'dagi o'zgarishni R
	// dan kechroq ko'rardi. 0 — chegara yo'q (LeaseTTL ishlatiladi).
	MaxFresh time.Duration

	// DialOptions — qo'shimcha gRPC sozlamalari. Testlarda bufconn
	// dialer'ini berish uchun; prod'da bo'sh qoladi.
	DialOptions []grpc.DialOption
}

// reconnectParams — edge→AP kanalining qayta ulanish sozlamalari.
//
// gRPC standarti (MaxDelay 120 s) bilan AP bir necha daqiqa yo'q bo'lsa,
// u qaytgach ham kanal ~2 daqiqagacha TRANSIENT_FAILURE'da qolardi: har
// Renew va Authorize darhol Unavailable olardi va AP'dagi o'zgarish 60 s
// ichida yetib bormasdi (DEV_SPEC §8). Kanal bitta, shuning uchun 2 s lik
// urinishlar AP'ga yuk emas.
var reconnectParams = grpc.ConnectParams{
	Backoff: backoff.Config{
		BaseDelay:  time.Second,
		Multiplier: 1.6,
		Jitter:     0.2,
		MaxDelay:   2 * time.Second,
	},
	// Javobsiz (blackhole) manzilga bitta urinish shu vaqtdan keyin
	// to'xtatiladi — ichki tarmoq uchun yetarli.
	MinConnectTimeout: 3 * time.Second,
}

// reconnectDelayMax — AP qayta erishiladigan bo'lgandan kanal qayta
// ulanguncha eng uzoq kutish: davom etayotgan urinish (MinConnectTimeout)
// + backoff (MaxDelay·(1+jitter)) = 3 + 2.4 s, yaxlitlangan. U
// config.AccessReconnectMax ga sig'ishi shart (testda tekshiriladi).
const reconnectDelayMax = 6 * time.Second

func Dial(opts Options) (*Client, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.Grace == 0 {
		opts.Grace = 15 * time.Minute
	}

	// TODO(Faza 1): mTLS. Hozircha ulanish ichki tarmoqda va loopback'da
	// (DEV_SPEC §7.2 S-11) — sertifikatlar Faza 1 da qo'shiladi.
	dialOptions := append(
		[]grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithConnectParams(reconnectParams),
		},
		opts.DialOptions...)

	conn, err := grpc.NewClient(opts.Address, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("access-server'ga ulanish (%s): %w", opts.Address, err)
	}

	return &Client{
		conn:     conn,
		service:  cc01v1.NewAccessInternalServiceClient(conn),
		timeout:  opts.Timeout,
		grace:    opts.Grace,
		maxFresh: opts.MaxFresh,
		cache:    make(map[string]*tokenCache),
	}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) Authorize(ctx context.Context, req Request) (*Grant, error) {
	key := keyOf(req)

	if grant, ok := c.cachedFresh(key); ok {
		return grant, nil
	}

	grant, started, err := c.call(ctx, req)
	if err != nil {
		var denial *Denial
		if errors.As(err, &denial) {
			// Rad javobi keshlanmaydi: bekor qilingan token qayta faollashmaydi,
			// lekin bo'shagan subdomain darhol ishlashi kerak.
			c.forgetDenied(key, denial.Code, started)
			return nil, err
		}

		// Tarmoq xatosi — fail-static. Kesh'da yaroqli yozuv bo'lsa uni
		// ishlatamiz; bo'lmasa rad etamiz (deny-by-default).
		if grant, ok := c.cachedUsable(key); ok {
			return grant, nil
		}
		return nil, err
	}

	c.store(key, grant)
	return grant, nil
}

// Renew ochiq tunnel ruxsatini AP'da qayta tekshiradi (Renewer).
//
// Keshni chetlab o'tadi va hech qachon keshdagi natijani qaytarmaydi —
// aks holda AP'dagi o'zgarish (tarif, bekor qilish) ochiq tunnelga
// yetib bormasdi. Natijalar:
//   - Grant — keshga yoziladi (keyingi ochilishlar uchun) va qaytariladi;
//   - *Denial — shu tokenga shu nomni hali berishi mumkin bo'lgan BARCHA
//     kesh yozuvlari o'chiriladi (forgetDenied) va rad javobi qaytariladi;
//   - boshqa har qanday xato — ErrUnavailable'ni o'rab qaytariladi.
func (c *Client) Renew(ctx context.Context, req Request) (*Grant, error) {
	req.Renewal = true
	key := keyOf(req)

	grant, started, err := c.call(ctx, req)
	if err != nil {
		var denial *Denial
		if errors.As(err, &denial) {
			c.forgetDenied(key, denial.Code, started)
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	c.store(key, grant)
	return grant, nil
}

// call AP'ga bitta AuthorizeTunnel RPC yuboradi. Keshga tegmaydi.
// Rad javobi *Denial sifatida, tarmoq xatosi oddiy xato sifatida qaytadi.
// started — RPC boshlangan vaqt: AP qarorini shu paytdan keyin qabul
// qilgan, shuning uchun yangilik (Grant.IssuedAt) ham, rad javobi izi ham
// shu nuqtadan hisoblanadi.
func (c *Client) call(ctx context.Context, req Request) (*Grant, time.Time, error) {
	started := time.Now()

	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	response, err := c.service.AuthorizeTunnel(callCtx, &cc01v1.AuthorizeTunnelRequest{
		Token:        req.Token,
		Protocol:     protoProtocol(req.Protocol),
		Subdomain:    req.Subdomain,
		CustomDomain: req.CustomDomain,
		CliVersion:   req.CliVersion,
		ClientIp:     req.ClientIP,
		Renewal:      req.Renewal,
	})
	if err != nil {
		return nil, started, fmt.Errorf("access-server javob bermadi: %w", err)
	}

	if denial := response.GetDenial(); denial != nil {
		return nil, started, &Denial{
			Code:    denialCode(denial.GetCode()),
			Message: denial.GetMessage(),
		}
	}

	grant := fromProto(response.GetGrant())
	grant.IssuedAt = started
	return grant, started, nil
}

// ─────────────────────────── kesh ───────────────────────────

func keyOf(req Request) cacheKey {
	sum := sha256.Sum256([]byte(req.Token))
	return cacheKey{
		token:        hex.EncodeToString(sum[:8]),
		subdomain:    req.Subdomain,
		customDomain: req.CustomDomain,
	}
}

func (c *Client) lookup(key cacheKey) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	tc, ok := c.cache[key.token]
	if !ok {
		return cacheEntry{}, false
	}
	entry, ok := tc.entries[key]
	return entry, ok
}

func (c *Client) cachedFresh(key cacheKey) (*Grant, bool) {
	entry, ok := c.lookup(key)
	if !ok || time.Now().After(entry.freshFor) {
		return nil, false
	}
	return entry.grant, true
}

func (c *Client) cachedUsable(key cacheKey) (*Grant, bool) {
	entry, ok := c.lookup(key)
	if !ok || time.Now().After(entry.usableFor) {
		return nil, false
	}
	return entry.grant, true
}

// freshness — keshdagi natija "yangi" hisoblanadigan muddat.
//
// Yangilash yoqilgan bo'lsa (maxFresh > 0) u edge'dagi yangilash oralig'iga
// teng: R = min(maxFresh, LeaseTTL/2) — renew.go'dagi renewInterval bilan
// bir xil. Shunda keshdan ochilgan tunnel ham AP'dagi o'zgarishni
// ≤ R + taymaut ichida ko'radi (DEV_SPEC §8). Yangilash o'chiq bo'lsa —
// LeaseTTL.
func (c *Client) freshness(leaseTTL time.Duration) time.Duration {
	fresh := leaseTTL
	if fresh <= 0 {
		fresh = time.Minute
	}
	if c.maxFresh <= 0 {
		return fresh
	}
	r := c.maxFresh
	if half := leaseTTL / 2; half > 0 && half < r {
		r = half
	}
	return min(fresh, r)
}

// store natijani keshga yozadi. Muddatlar javob kelgan paytdan emas,
// grant.IssuedAt'dan (RPC boshlanishi) hisoblanadi, yangilik esa R bilan
// cheklanadi (freshness) — shunda keshdan ochilgan tunnel ham AP'dagi
// o'zgarishni yangilash oralig'idan kechroq ko'rmaydi.
//
// Yozish monoton: mavjud yozuv yangiroq (IssuedAt keyinroq) bo'lsa, eski
// natija uning ustiga yozilmaydi — parallel yangilanishlar tartibsiz
// qaytsa ham limitlar orqaga qaytmaydi. Xuddi shunday, rad javobi izidan
// (tombstone) oldin boshlangan RPC'ning grant'i umuman yozilmaydi.
func (c *Client) store(key cacheKey, grant *Grant) {
	issued := grant.IssuedAt
	if issued.IsZero() {
		issued = time.Now()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(time.Now())

	tc := c.cache[key.token]
	if tc == nil {
		tc = &tokenCache{}
		c.cache[key.token] = tc
	}
	if tc.deniedSince(key, grant.Subdomain, issued) {
		return
	}
	if existing, ok := tc.entries[key]; ok && existing.grant.IssuedAt.After(grant.IssuedAt) {
		return
	}
	if tc.entries == nil {
		tc.entries = make(map[cacheKey]cacheEntry)
	}
	tc.entries[key] = cacheEntry{
		grant:     grant,
		freshFor:  issued.Add(c.freshness(grant.LeaseTTL)),
		usableFor: issued.Add(c.grace),
	}
}

// tokenScopedDenial — rad javobi tokenning o'ziga tegishlimi (qaysi nom
// so'ralganidan qat'i nazar). Bunday rad javobidan keyin tokenning hech bir
// kesh yozuvi ishlatilmasligi kerak.
func tokenScopedDenial(code string) bool {
	switch code {
	case "TOKEN_INVALID", "TOKEN_REVOKED", "TOKEN_EXPIRED",
		"PLAN_SUSPENDED", "EMAIL_NOT_VERIFIED":
		return true
	default:
		return false
	}
}

// forgetDenied rad javobidan keyin shu tokenga shu nomni hali berishi
// mumkin bo'lgan BARCHA kesh yozuvlarini o'chiradi va iz qoldiradi.
//
//   - Token darajasidagi rad (tokenScopedDenial) — tokenning hamma yozuvlari.
//   - Boshqa rad — so'ralgan subdomain kalitidagi yozuvlar, BERILGAN nomi
//     shu subdomain bo'lgan yozuvlar (masalan, klient bo'sh subdomain bilan
//     ochgan, AP esa aynan shu nomni tanlagan — kalitda "" turadi) va shu
//     custom domain yozuvlari.
//
// Iz sifatida rad javobi RPC'si boshlangan vaqt yoziladi: undan oldin
// boshlangan va hali yo'lda bo'lgan grant keshni qayta tiriltira olmaydi.
// Ortiqcha o'chirish xavfsiz — narxi bitta qo'shimcha AP chaqiruvi.
func (c *Client) forgetDenied(key cacheKey, code string, started time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(time.Now())

	tc := c.cache[key.token]
	if tc == nil {
		tc = &tokenCache{}
		c.cache[key.token] = tc
	}

	if tokenScopedDenial(code) {
		clear(tc.entries)
		tc.deniedAt = later(tc.deniedAt, started)
		return
	}

	for k, entry := range tc.entries {
		if deniedName(k, entry.grant.Subdomain, key) {
			delete(tc.entries, k)
		}
	}
	if tc.subDeniedAt == nil {
		tc.subDeniedAt = make(map[string]time.Time)
	}
	tc.subDeniedAt[key.subdomain] = later(tc.subDeniedAt[key.subdomain], started)
	if key.customDomain != "" {
		if tc.domainDeniedAt == nil {
			tc.domainDeniedAt = make(map[string]time.Time)
		}
		tc.domainDeniedAt[key.customDomain] = later(tc.domainDeniedAt[key.customDomain], started)
	}
}

// deniedName — k kalitidagi (berilgan nomi granted bo'lgan) yozuv denied
// kalitiga kelgan nom darajasidagi rad javobi doirasiga kiradimi.
func deniedName(k cacheKey, granted string, denied cacheKey) bool {
	switch {
	case k.subdomain == denied.subdomain:
		return true
	case denied.subdomain != "" && granted == denied.subdomain:
		return true
	case denied.customDomain != "" && k.customDomain == denied.customDomain:
		return true
	default:
		return false
	}
}

// deniedSince — issued paytda boshlangan RPC'ning grant'i rad javobi izi
// bilan yopilganmi (iz undan keyin yoki aynan o'sha paytda boshlangan).
func (tc *tokenCache) deniedSince(key cacheKey, granted string, issued time.Time) bool {
	covers := func(at time.Time) bool { return !at.IsZero() && !issued.After(at) }

	if covers(tc.deniedAt) || covers(tc.subDeniedAt[key.subdomain]) {
		return true
	}
	if granted != "" && covers(tc.subDeniedAt[granted]) {
		return true
	}
	return key.customDomain != "" && covers(tc.domainDeniedAt[key.customDomain])
}

// tombstoneTTL — iz qancha saqlanadi. Undan oldin boshlangan har qanday
// RPC c.timeout ichida tugaydi, shuning uchun 2·timeout + zaxiradan keyin
// iz kerak emas.
func (c *Client) tombstoneTTL() time.Duration { return 2*c.timeout + 5*time.Second }

// sweepLocked eskirgan yozuvlarni (grace tugagan) va izlarni o'chiradi —
// noto'g'ri tokenlar bilan to'xtovsiz so'rovlar xotirani to'ldirmasligi
// uchun. Har tombstoneTTL da ko'pi bilan bir marta ishlaydi. c.mu ostida.
func (c *Client) sweepLocked(now time.Time) {
	ttl := c.tombstoneTTL()
	if now.Sub(c.lastSweep) < ttl {
		return
	}
	c.lastSweep = now
	cutoff := now.Add(-ttl)

	for token, tc := range c.cache {
		for k, entry := range tc.entries {
			if now.After(entry.usableFor) {
				delete(tc.entries, k)
			}
		}
		if tc.deniedAt.Before(cutoff) {
			tc.deniedAt = time.Time{}
		}
		maps.DeleteFunc(tc.subDeniedAt, func(_ string, at time.Time) bool { return at.Before(cutoff) })
		maps.DeleteFunc(tc.domainDeniedAt, func(_ string, at time.Time) bool { return at.Before(cutoff) })

		if len(tc.entries) == 0 && tc.deniedAt.IsZero() &&
			len(tc.subDeniedAt) == 0 && len(tc.domainDeniedAt) == 0 {
			delete(c.cache, token)
		}
	}
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// ─────────────────────── proto ↔ Go ───────────────────────

func protoProtocol(name string) cc01v1.Protocol {
	switch name {
	case "http":
		return cc01v1.Protocol_PROTOCOL_HTTP
	case "tcp":
		return cc01v1.Protocol_PROTOCOL_TCP
	default:
		return cc01v1.Protocol_PROTOCOL_UNSPECIFIED
	}
}

func fromProto(g *cc01v1.Grant) *Grant {
	limits := g.GetLimits()
	return &Grant{
		UserID:            g.GetUserId(),
		TenantID:          g.GetTenantId(),
		Plan:              g.GetPlan(),
		Subdomain:         g.GetSubdomain(),
		MaxTunnels:        int(limits.GetMaxTunnels()),
		MaxConnsPerTunnel: int(limits.GetMaxConnsPerTunnel()),
		BandwidthBps:      limits.GetBandwidthBps(),
		LeaseTTL:          time.Duration(g.GetLeaseTtlS()) * time.Second,
	}
}

// denialCode proto enum nomini qisqa kodga aylantiradi:
// DENIAL_CODE_TOKEN_REVOKED → TOKEN_REVOKED.
func denialCode(code cc01v1.DenialCode) string {
	const prefix = "DENIAL_CODE_"
	name := code.String()
	if len(name) > len(prefix) && name[:len(prefix)] == prefix {
		return name[len(prefix):]
	}
	return name
}

// ─────────────────── testlar uchun yordamchilar ───────────────────

// expireFreshness lease muddatini tugagan qilib belgilaydi, lekin grace
// oynasini saqlaydi — fail-static yo'lini sinash uchun.
func (c *Client) expireFreshness(key cacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if tc, ok := c.cache[key.token]; ok {
		if entry, ok := tc.entries[key]; ok {
			entry.freshFor = time.Now().Add(-time.Second)
			tc.entries[key] = entry
		}
	}
}

// expireEntry yozuvni butunlay eskirgan qilib belgilaydi.
func (c *Client) expireEntry(key cacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if tc, ok := c.cache[key.token]; ok {
		if entry, ok := tc.entries[key]; ok {
			past := time.Now().Add(-time.Second)
			entry.freshFor, entry.usableFor = past, past
			tc.entries[key] = entry
		}
	}
}
