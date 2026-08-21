package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	cc01v1 "github.com/freco-dev/cc01/core-server/gen/cc01/v1"
	"google.golang.org/grpc"
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

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	grant     *Grant
	freshFor  time.Time // shu vaqtgacha qayta so'ramaymiz
	usableFor time.Time // AP yiqilsa shu vaqtgacha ishlatiladi
}

// Options — klient sozlamalari.
type Options struct {
	Address string
	Timeout time.Duration
	Grace   time.Duration

	// DialOptions — qo'shimcha gRPC sozlamalari. Testlarda bufconn
	// dialer'ini berish uchun; prod'da bo'sh qoladi.
	DialOptions []grpc.DialOption
}

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
		[]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())},
		opts.DialOptions...)

	conn, err := grpc.NewClient(opts.Address, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("access-server'ga ulanish (%s): %w", opts.Address, err)
	}

	return &Client{
		conn:    conn,
		service: cc01v1.NewAccessInternalServiceClient(conn),
		timeout: opts.Timeout,
		grace:   opts.Grace,
		cache:   make(map[string]cacheEntry),
	}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) Authorize(ctx context.Context, req Request) (*Grant, error) {
	key := cacheKey(req)

	if grant, ok := c.cachedFresh(key); ok {
		return grant, nil
	}

	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	response, err := c.service.AuthorizeTunnel(callCtx, &cc01v1.AuthorizeTunnelRequest{
		Token:        req.Token,
		Protocol:     protoProtocol(req.Protocol),
		Subdomain:    req.Subdomain,
		CustomDomain: req.CustomDomain,
		CliVersion:   req.CliVersion,
		ClientIp:     req.ClientIP,
	})
	if err != nil {
		// Tarmoq xatosi — fail-static. Kesh'da yaroqli yozuv bo'lsa uni
		// ishlatamiz; bo'lmasa rad etamiz (deny-by-default).
		if grant, ok := c.cachedUsable(key); ok {
			return grant, nil
		}
		return nil, fmt.Errorf("access-server javob bermadi: %w", err)
	}

	if denial := response.GetDenial(); denial != nil {
		// Rad javobi keshlanmaydi: bekor qilingan token qayta faollashmaydi,
		// lekin bo'shagan subdomain darhol ishlashi kerak.
		c.forget(key)
		return nil, &Denial{
			Code:    denialCode(denial.GetCode()),
			Message: denial.GetMessage(),
		}
	}

	grant := fromProto(response.GetGrant())
	c.store(key, grant)
	return grant, nil
}

// ─────────────────────────── kesh ───────────────────────────

// cacheKey tokenning o'zini emas, uning hashini ishlatadi — xom token
// xotiradagi map kalitlarida qolib ketmasligi uchun.
func cacheKey(req Request) string {
	sum := sha256.Sum256([]byte(req.Token))
	return hex.EncodeToString(sum[:8]) + "|" + req.Subdomain + "|" + req.CustomDomain
}

func (c *Client) cachedFresh(key string) (*Grant, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.cache[key]
	if !ok || time.Now().After(entry.freshFor) {
		return nil, false
	}
	return entry.grant, true
}

func (c *Client) cachedUsable(key string) (*Grant, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.cache[key]
	if !ok || time.Now().After(entry.usableFor) {
		return nil, false
	}
	return entry.grant, true
}

func (c *Client) store(key string, grant *Grant) {
	ttl := grant.LeaseTTL
	if ttl <= 0 {
		ttl = time.Minute
	}

	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = cacheEntry{
		grant:     grant,
		freshFor:  now.Add(ttl),
		usableFor: now.Add(c.grace),
	}
}

func (c *Client) forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, key)
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
func (c *Client) expireFreshness(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.cache[key]; ok {
		entry.freshFor = time.Now().Add(-time.Second)
		c.cache[key] = entry
	}
}

// expireEntry yozuvni butunlay eskirgan qilib belgilaydi.
func (c *Client) expireEntry(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.cache[key]; ok {
		past := time.Now().Add(-time.Second)
		entry.freshFor, entry.usableFor = past, past
		c.cache[key] = entry
	}
}
