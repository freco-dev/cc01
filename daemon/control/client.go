// Package control cc01d ni Control Plane bilan bog'laydi.
//
// Vazifasi bitta: CP dan kelgan NetworkMap ni routerdagi peerlarga
// aylantirish. Shundan keyin mesh qo'lda sozlashsiz ishlaydi.
package control

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/router"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config — klient sozlamalari.
type Config struct {
	// Address — CP ning gRPC manzili.
	Address string

	// Identity — shu nodening kalit jufti.
	Identity *noise.Identity

	// Router — peerlar shu yerga qo'shiladi.
	Router *router.Router

	Tenant   string
	Hostname string
	Tags     []string

	// Endpoints — bizning underlay manzillarimiz.
	Endpoints []netip.AddrPort

	// AuthToken — CP bilan kelishilgan sir.
	AuthToken string

	// OnRelays — relay ro'yxati kelganda chaqiriladi.
	//
	// Klient relayga o'zi ulanmaydi: relay klienti datapath soketini
	// talab qiladi, u esa engine bilan birga tug'iladi. Shuning uchun
	// ro'yxat yuqoriga uzatiladi.
	OnRelays func([]RelayInfo)

	// OnNetworkMap har bir qo'llangan NetworkMap dan KEYIN chaqiriladi.
	//
	// Peerlar o'zgardi degani marshrutlar ham o'zgargan bo'lishi
	// mumkin. Chaqiruv NetworkMap oqimi ichida bajariladi, shuning
	// uchun u bloklanmasligi shart.
	OnNetworkMap func()

	// Pins — CP sertifikatining kutilayotgan SPKI pinlari
	// ("sha256/…"). Bir nechtasi kalit almashtirish uchun.
	Pins []string

	// Insecure — kanalni shifrlamasdan ochish. FAQAT lokal
	// sinovlar uchun: bu rejimda NetworkMap, node kalitlari va
	// autentifikatsiya tokeni ochiq matnda uzatiladi.
	Insecure bool

	// ClientCert — nodening TLS klient sertifikati.
	//
	// Bo'sh bo'lsa node faqat token bilan tanitiladi va CP
	// ogohlantirish yozadi: token umumiy sir, ya'ni himoya
	// sezilarli darajada zaifroq.
	ClientCert *tls.Certificate

	Logger *slog.Logger
}

// RelayInfo — CP e'lon qilgan relay tuguni.
type RelayInfo struct {
	ID        string
	PublicKey noise.PublicKey
	Endpoint  netip.AddrPort
	Region    string
	Priority  uint32
}

// Client — CP bilan aloqani ushlab turuvchi.
type Client struct {
	conn    *grpc.ClientConn
	service cc01v1.ControlServiceClient
	cfg     Config
	log     *slog.Logger

	nodeID  string
	address netip.Prefix
}

// Registration — ro'yxatdan o'tish natijasi.
type Registration struct {
	NodeID string

	// Address — bizga berilgan overlay manzili.
	Address netip.Prefix

	// TenantCIDR — tenant segmenti; TUN marshruti shunga qo'yiladi.
	TenantCIDR netip.Prefix

	HeartbeatInterval time.Duration
}

func Dial(cfg Config) (*Client, error) {
	if cfg.Identity == nil {
		return nil, errors.New("control: identity berilmagan")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	creds, err := transportCredentials(cfg, logger)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(cfg.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("control: CP ga ulanish (%s): %w", cfg.Address, err)
	}

	return &Client{
		conn:    conn,
		service: cc01v1.NewControlServiceClient(conn),
		cfg:     cfg,
		log:     logger.With("component", "control"),
	}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

// SetRouter routerni ulaydi.
//
// Ro'yxatdan o'tish TUN va engine yaratishdan OLDIN bo'ladi (manzil
// aynan o'shanda beriladi), router esa engine bilan birga tug'iladi —
// shuning uchun u keyinroq ulanadi.
func (c *Client) SetRouter(r *router.Router) { c.cfg.Router = r }

// NodeID — CP bergan identifikator.
func (c *Client) NodeID() string { return c.nodeID }

// Register nodeni CP da ro'yxatga oladi va manzil oladi.
func (c *Client) Register(ctx context.Context) (*Registration, error) {
	key := c.cfg.Identity.PublicKey()

	endpoints := make([]string, 0, len(c.cfg.Endpoints))
	for _, endpoint := range c.cfg.Endpoints {
		endpoints = append(endpoints, endpoint.String())
	}

	// Oldingi manzilni so'raymiz (sticky): qayta ulanganda IP
	// o'zgarmasligi uchun.
	var preferred string
	if c.address.IsValid() {
		preferred = c.address.String()
	}

	response, err := c.service.Register(ctx, &cc01v1.RegisterRequest{
		PublicKey:        key[:],
		Tenant:           c.cfg.Tenant,
		Hostname:         c.cfg.Hostname,
		Endpoints:        endpoints,
		Tags:             c.cfg.Tags,
		PreferredAddress: preferred,
		AuthToken:        c.cfg.AuthToken,
	})
	if err != nil {
		return nil, fmt.Errorf("control: ro'yxatdan o'tish: %w", err)
	}

	address, err := netip.ParsePrefix(response.GetAddress())
	if err != nil {
		return nil, fmt.Errorf("control: CP noto'g'ri manzil berdi (%q): %w",
			response.GetAddress(), err)
	}

	tenantCIDR, err := netip.ParsePrefix(response.GetTenantCidr())
	if err != nil {
		return nil, fmt.Errorf("control: CP noto'g'ri tenant CIDR berdi (%q): %w",
			response.GetTenantCidr(), err)
	}

	c.nodeID = response.GetNodeId()
	c.address = address

	interval := time.Duration(response.GetHeartbeatIntervalS()) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}

	c.log.Info("ro'yxatdan o'tildi",
		"node", shortID(c.nodeID), "address", address, "tenant_cidr", tenantCIDR)

	return &Registration{
		NodeID:            c.nodeID,
		Address:           address,
		TenantCIDR:        tenantCIDR,
		HeartbeatInterval: interval,
	}, nil
}

// Run NetworkMap stream'ini kuzatadi va heartbeat yuboradi.
//
// `ctx` bekor qilinmaguncha ishlaydi. Stream uzilsa qayta ulanadi:
// CP vaqtincha yiqilsa mesh ishlashda davom etadi (fail-static).
func (c *Client) Run(ctx context.Context, heartbeat time.Duration) error {
	go c.heartbeatLoop(ctx, heartbeat)

	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		err := c.watch(ctx)
		if err == nil || ctx.Err() != nil {
			return nil
		}

		c.log.Warn("NetworkMap stream uzildi, qayta ulanamiz",
			"err", err, "backoff", backoff)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		backoff = min(backoff*2, maxBackoff)
	}
}

// watch bitta stream sessiyasini boshqaradi.
func (c *Client) watch(ctx context.Context) error {
	stream, err := c.service.WatchNetworkMap(ctx, &cc01v1.WatchNetworkMapRequest{
		NodeId:    c.nodeID,
		AuthToken: c.cfg.AuthToken,
		// Har doim 0: qayta ulanganda to'liq map olamiz. Stream
		// uzilganda nima o'tkazib yuborganimizni bilmaymiz, shuning
		// uchun to'liq holat xavfsizroq.
		Since: 0,
	})
	if err != nil {
		return err
	}

	for {
		netmap, err := stream.Recv()
		if err != nil {
			return err
		}
		c.apply(netmap)
	}
}

func (c *Client) heartbeatLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			endpoints := make([]string, 0, len(c.cfg.Endpoints))
			for _, endpoint := range c.cfg.Endpoints {
				endpoints = append(endpoints, endpoint.String())
			}

			if _, err := c.service.Heartbeat(ctx, &cc01v1.HeartbeatRequest{
				NodeId:    c.nodeID,
				Endpoints: endpoints,
				AuthToken: c.cfg.AuthToken,
			}); err != nil && ctx.Err() == nil {
				c.log.Debug("heartbeat muvaffaqiyatsiz", "err", err)
			}
		}
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// transportCredentials kanalning himoyasini tanlaydi.
//
// Standart — TLS 1.3. Shifrlanmagan kanal FAQAT oshkora so'ralganda
// ochiladi va bu haqda ogohlantiriladi: bu kanal orqali butun
// NetworkMap (kim tarmoqda, qaysi manzilda) va autentifikatsiya
// tokeni o'tadi.
func transportCredentials(cfg Config, logger *slog.Logger) (credentials.TransportCredentials, error) {
	if cfg.Insecure {
		if len(cfg.Pins) > 0 {
			return nil, errors.New(
				"control: -cp-insecure va -cp-pin birga berilmaydi; qaysi biri kerakligini tanlang")
		}

		logger.Warn("CP KANALI SHIFRLANMAGAN — NetworkMap va token ochiq matnda uzatiladi; " +
			"faqat lokal sinov uchun")
		return insecure.NewCredentials(), nil
	}

	if len(cfg.Pins) == 0 {
		// Pin bo'lmasa tizim ildiz sertifikatlariga tayanamiz. Bu
		// ishlaydi, lekin self-signed CP uchun emas — shuning uchun
		// aniq maslahat beramiz.
		logger.Info("CP sertifikati tizim ildizlari bilan tekshiriladi",
			"maslahat", "self-signed CP uchun -cp-pin bering")
	}

	config := tlsConfig(serverNameFor(cfg.Address), cfg.Pins)
	if cfg.ClientCert != nil {
		config.Certificates = []tls.Certificate{*cfg.ClientCert}
	}

	return credentials.NewTLS(config), nil
}

// serverNameFor manzildan TLS uchun host qismini ajratadi.
func serverNameFor(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}
