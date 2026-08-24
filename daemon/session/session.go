// Package session mesh ulanishining hayot siklini boshqaradi.
//
// Nega alohida qatlam: `cc01 up` va `cc01 down` demonni to'xtatmasdan
// mesh'ni ko'taradi va tushiradi. Ya'ni datapath, Control Plane
// ulanishi va marshrutlar demon jarayonidan qisqaroq umr ko'radi va
// bir necha marta qayta qurilishi mumkin. Ilgari bularning hammasi
// `main` ichida chiziqli qurilardi va faqat signal bilan tugardi.
package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/control"
	"github.com/freco-dev/cc01/daemon/engine"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/route"
	"github.com/freco-dev/cc01/daemon/tcpolicy"
	"github.com/freco-dev/cc01/daemon/tun"
)

// ErrAlreadyUp — mesh allaqachon ko'tarilgan.
//
// Down qaytadan chaqirilsa xato EMAS: "tushirilgan bo'lsin" degan
// talab allaqachon bajarilgan. Up esa boshqacha — konfiguratsiya
// farq qilishi mumkin, jimgina e'tiborsiz qoldirish yanglish bo'lardi.
var ErrAlreadyUp = errors.New("session: mesh allaqachon ko'tarilgan")

// Config — mesh'ni ko'tarish uchun kerakli hamma narsa.
type Config struct {
	Identity    *noise.Identity
	ControlAddr string
	Tenant      string
	Hostname    string
	AuthToken   string
	ListenPort  uint16
	IfaceName   string

	// Advertised — qo'lda ko'rsatilgan underlay manzillar. Bo'sh
	// bo'lsa mahalliy interfeyslardan yig'iladi.
	Advertised []netip.AddrPort

	// StunServer — bo'sh bo'lmasa, ro'yxatdan o'tishdan OLDIN public
	// manzil aniqlanadi.
	StunServer netip.AddrPort

	// Pins — CP sertifikatining kutilayotgan SPKI pinlari.
	Pins []string

	// Insecure — CP kanalini shifrlamaslik (FAQAT lokal sinov).
	Insecure bool

	// ClientCert — nodening TLS klient sertifikati.
	ClientCert *tls.Certificate

	// Tags — mikrosegmentatsiya tag'lari. CP ularni ACL da
	// `tag:<nom>` sifatida yechadi.
	Tags []string

	// Firewall — overlay interfeysida eBPF policy filtrini yoqish.
	//
	// Xato bo'lsa mesh baribir ko'tariladi: filtr kuzatuv va
	// himoya vositasi, uning yo'qligi ulanishni to'xtatish uchun
	// sabab emas.
	Firewall bool

	// FirewallEnforce — filtr hukmni qo'llaydimi. false bo'lsa
	// dry-run.
	//
	// ⚠️ Standart holatda FALSE. Deny-by-default siyosatida
	// qoidalar hali yozilmagan bo'lsa, enforce butun overlay
	// trafigini kesib qo'yardi.
	FirewallEnforce bool

	Logger *slog.Logger
}

// Session — ko'tarilgan yoki tushirilgan mesh.
//
// Barcha metodlar bir vaqtda chaqirilishi mumkin.
type Session struct {
	cfg Config
	log *slog.Logger

	mu     sync.Mutex
	active *active
}

// active — bitta ko'tarilish davomida yashaydigan narsalar.
type active struct {
	device       *tun.Device
	engine       *engine.Engine
	client       *control.Client
	relay        *relayLink
	routes       *route.Reconciler
	registration *control.Registration
	endpoints    []netip.AddrPort
	policy       *tcpolicy.Filter
	since        time.Time

	cancel context.CancelFunc
	done   sync.WaitGroup
}

func New(cfg Config) *Session {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Session{cfg: cfg, log: cfg.Logger}
}

// Up mesh'ni ko'taradi.
//
// Ketma-ketlik muhim:
//  1. UDP soketi ochiladi — endpointni e'lon qilish uchun port kerak
//  2. STUN so'raladi — NAT ortida public manzil
//  3. CP da ro'yxatdan o'tiladi — overlay manzili aynan shu yerda beriladi
//  4. TUN yaratiladi — manzil endi ma'lum
//  5. Engine, marshrutlar, CP oqimi ishga tushadi
//
// Har qanday bosqichdagi xato shu paytgacha ochilganlarni yopadi:
// yarim ko'tarilgan mesh qolmasligi kerak.
func (s *Session) Up(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active != nil {
		return ErrAlreadyUp
	}

	built, err := s.build(ctx)
	if err != nil {
		return err
	}

	s.active = built
	return nil
}

func (s *Session) build(ctx context.Context) (*active, error) {
	bind, err := conn.Open(s.cfg.ListenPort)
	if err != nil {
		return nil, err
	}

	endpoints := s.cfg.Advertised
	if len(endpoints) == 0 {
		endpoints = localEndpoints(bind.Port())
	}
	if len(endpoints) == 0 {
		_ = bind.Close()
		return nil, fmt.Errorf("session: underlay manzil topilmadi; -advertise bilan ko'rsating")
	}

	// STUN engine'dan OLDIN so'raladi: NAT bog'lanishi soketga
	// bog'langan, boshqa soketdan so'ralgan manzil yaroqsiz bo'lardi.
	if s.cfg.StunServer.IsValid() {
		if mapped, err := discoverPublic(bind, s.cfg.StunServer); err != nil {
			s.log.Warn("public manzil aniqlanmadi, lokal manzillar ishlatiladi",
				"stun", s.cfg.StunServer, "err", err)
		} else {
			s.log.Info("public manzil aniqlandi", "endpoint", mapped)
			endpoints = append([]netip.AddrPort{mapped}, endpoints...)
		}
	}

	relay := newRelayLink(s.cfg.Identity, bind, s.log)

	// Marshrut rekonsilyatori va policy filtri TUN yaratilgandan
	// keyin tug'iladi, lekin ularga murojaat qiladigan NetworkMap
	// oqimi undan oldin ulanadi.
	var routes routeHandle
	var policyHandle policyHandle

	client, err := control.Dial(control.Config{
		Address:      s.cfg.ControlAddr,
		Identity:     s.cfg.Identity,
		Tenant:       s.cfg.Tenant,
		Hostname:     s.cfg.Hostname,
		Tags:         taggedNames(s.cfg.Tags),
		Endpoints:    endpoints,
		AuthToken:    s.cfg.AuthToken,
		OnRelays:     relay.update,
		OnNetworkMap: routes.poke,
		Policy:       &policyHandle,
		Pins:         s.cfg.Pins,
		Insecure:     s.cfg.Insecure,
		ClientCert:   s.cfg.ClientCert,
		Logger:       s.log,
	})
	if err != nil {
		_ = bind.Close()
		return nil, err
	}

	runCtx, cancel := context.WithCancel(context.Background())

	// Ro'yxatdan o'tish chaqiruvchining ctx'i bilan cheklanadi —
	// u vaqt chegarasi qo'ygan bo'lishi mumkin.
	registration, err := client.Register(ctx)
	if err != nil {
		cancel()
		_ = client.Close()
		_ = bind.Close()
		return nil, err
	}

	device, err := tun.Create(tun.Config{
		Name:      s.cfg.IfaceName,
		Addresses: []netip.Prefix{registration.Address},
		Routes:    []netip.Prefix{registration.TenantCIDR},
	})
	if err != nil {
		cancel()
		_ = client.Close()
		_ = bind.Close()
		return nil, err
	}

	datapath, err := engine.New(engine.Config{
		Identity: s.cfg.Identity,
		Device:   device,
		Bind:     bind,
		Logger:   s.log,
	})
	if err != nil {
		cancel()
		_ = client.Close()
		_ = device.Close()
		_ = bind.Close()
		return nil, err
	}

	// Router engine bilan birga tug'iladi, ro'yxatdan o'tish esa
	// undan oldin bo'ladi — shuning uchun uni endi ulaymiz.
	client.SetRouter(datapath.Router())
	relay.attach(datapath)
	datapath.Start()

	reconciler := route.New(route.Config{
		Base:   []netip.Prefix{registration.TenantCIDR},
		Peers:  datapath.Router(),
		Sink:   device,
		Logger: s.log,
	})
	routes.set(reconciler)

	// eBPF policy filtri TUN yaratilgandan keyin biriktiriladi:
	// u aynan `cc0` da, ochilgan ichki paketlar ustidan ishlaydi.
	var policy *tcpolicy.Filter
	if s.cfg.Firewall {
		policy, err = tcpolicy.Load(tcpolicy.Config{
			Interface: device.Name(),
			Enforce:   s.cfg.FirewallEnforce,
			Logger:    s.log,
		})
		if err != nil {
			// Mesh baribir ko'tariladi: filtrsiz ham ulanish
			// ishlaydi, faqat policy qo'llanmaydi.
			s.log.Warn("eBPF policy filtri yuklanmadi", "err", err)
			policy = nil
		}
	}
	policyHandle.set(policy)

	built := &active{
		device:       device,
		engine:       datapath,
		client:       client,
		relay:        relay,
		routes:       reconciler,
		registration: registration,
		endpoints:    endpoints,
		policy:       policy,
		since:        time.Now(),
		cancel:       cancel,
	}

	built.done.Add(2)
	go func() {
		defer built.done.Done()
		reconciler.Run(runCtx)
	}()
	go func() {
		defer built.done.Done()
		if err := client.Run(runCtx, registration.HeartbeatInterval); err != nil {
			s.log.Error("CP klienti to'xtadi", "err", err)
		}
	}()

	s.log.Info("mesh ko'tarildi",
		"pubkey", s.cfg.Identity.PublicKey().String(),
		"node", shortID(registration.NodeID),
		"iface", device.Name(),
		"addr", registration.Address.String(),
		"cp", s.cfg.ControlAddr)

	return built, nil
}

// Down mesh'ni tushiradi. Allaqachon tushirilgan bo'lsa — xato emas.
//
// Tartib teskari: avval fon oqimlari to'xtaydi, keyin datapath.
// Aks holda to'xtayotgan CP oqimi yopilgan routerga yozishga
// urinardi.
func (s *Session) Down() error {
	s.mu.Lock()
	current := s.active
	s.active = nil
	s.mu.Unlock()

	if current == nil {
		return nil
	}

	current.cancel()
	current.done.Wait()
	current.relay.close()

	if current.policy != nil {
		if err := current.policy.Close(); err != nil {
			s.log.Warn("policy filtrini ajratish", "err", err)
		}
	}

	// Marshrutlarni engine'dan OLDIN tozalaymiz: `Close()` interfeysni
	// o'chiradi va u bilan birga marshrutlar ham ketadi, lekin holatni
	// aniq bo'shatgan yaxshi — DoD "0 orphan marshrut" ni Close'ning
	// nozik xatti-harakatiga tashlab qo'ymaymiz.
	if _, err := current.device.SetRoutes(nil); err != nil {
		s.log.Warn("marshrutlarni tozalash", "err", err)
	}

	err := errors.Join(current.engine.Close(), current.client.Close())

	s.log.Info("mesh tushirildi")
	return err
}

// IsUp — mesh ko'tarilganmi.
func (s *Session) IsUp() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.active != nil
}

// routeHandle — rekonsilyator hali yaratilmagan paytda kelgan
// turtkilarni yutib yuboradigan indirection.
//
// Halqa: CP klienti turtki manbai, lekin u rekonsilyatordan OLDIN
// tug'iladi (rekonsilyatorga TUN kerak, TUN'ga esa ro'yxatdan o'tish).
type routeHandle struct {
	mu    sync.Mutex
	inner *route.Reconciler
}

func (h *routeHandle) set(r *route.Reconciler) {
	h.mu.Lock()
	h.inner = r
	h.mu.Unlock()
}

func (h *routeHandle) poke() {
	h.mu.Lock()
	inner := h.inner
	h.mu.Unlock()

	if inner != nil {
		inner.Poke()
	}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Status — mesh holatining bir lahzalik surati.
type Status struct {
	PublicKey    noise.PublicKey
	NodeID       string
	Hostname     string
	Tenant       string
	Address      string
	Interface    string
	ControlPlane string
	RelayID      string
	ListenPort   uint16
	Endpoints    []string
	Routes       route.Status
	Since        time.Time
}

// Status joriy holatni qaytaradi. Ikkinchi qiymat false bo'lsa mesh
// tushirilgan va birinchisi ma'nosiz.
func (s *Session) Status() (Status, bool) {
	s.mu.Lock()
	current := s.active
	s.mu.Unlock()

	if current == nil {
		return Status{}, false
	}

	endpoints := make([]string, 0, len(current.endpoints))
	for _, endpoint := range current.endpoints {
		endpoints = append(endpoints, endpoint.String())
	}

	return Status{
		PublicKey:    s.cfg.Identity.PublicKey(),
		NodeID:       current.registration.NodeID,
		Hostname:     s.cfg.Hostname,
		Tenant:       s.cfg.Tenant,
		Address:      current.registration.Address.String(),
		Interface:    current.device.Name(),
		ControlPlane: s.cfg.ControlAddr,
		RelayID:      current.relay.activeID(),
		ListenPort:   current.engine.ListenPort(),
		Endpoints:    endpoints,
		Routes:       current.routes.Status(),
		Since:        current.since,
	}, true
}

// Peers — datapath ko'rayotgan peerlar. Mesh tushirilgan bo'lsa bo'sh.
func (s *Session) Peers() []engine.PeerSnapshot {
	s.mu.Lock()
	current := s.active
	s.mu.Unlock()

	if current == nil {
		return nil
	}
	return current.engine.Snapshot()
}

// Policy — joriy eBPF filtri; mesh tushirilgan yoki filtr
// yuklanmagan bo'lsa nil.
//
// IPC xizmati buni HAR CHAQIRUVDA so'raydi: soket mesh'dan oldin
// ochiladi va filtr keyinroq paydo bo'ladi.
func (s *Session) Policy() *tcpolicy.Filter {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active == nil {
		return nil
	}
	return s.active.policy
}

// policyHandle — filtr hali yaratilmagan paytda kelgan CP
// qoidalarini yutib yuboradigan indirection.
//
// Halqa: CP klienti qoidalarni olib keladi, lekin u filtrdan OLDIN
// tug'iladi (filtrga TUN kerak, TUN'ga esa ro'yxatdan o'tish).
//
// Filtr yo'q bo'lsa qoidalar jimgina tashlanadi: CP keyingi
// yangilanishda ularni qayta yuboradi, chunki node policy
// versiyasini eslab qolmaydi.
type policyHandle struct {
	mu    sync.Mutex
	inner *tcpolicy.Filter
}

func (h *policyHandle) set(filter *tcpolicy.Filter) {
	h.mu.Lock()
	h.inner = filter
	h.mu.Unlock()
}

func (h *policyHandle) current() *tcpolicy.Filter {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.inner
}

func (h *policyHandle) IdentityFor(prefix netip.Prefix) (uint32, error) {
	filter := h.current()
	if filter == nil {
		return 0, control.ErrNoPolicyFilter
	}
	return filter.IdentityFor(prefix)
}

func (h *policyHandle) AddRule(rule tcpolicy.Rule) error {
	filter := h.current()
	if filter == nil {
		return control.ErrNoPolicyFilter
	}
	return filter.AddRule(rule)
}

func (h *policyHandle) RemoveRule(rule tcpolicy.Rule) error {
	filter := h.current()
	if filter == nil {
		return control.ErrNoPolicyFilter
	}
	return filter.RemoveRule(rule)
}

func (h *policyHandle) Rules() ([]tcpolicy.RuleStatus, error) {
	filter := h.current()
	if filter == nil {
		return nil, control.ErrNoPolicyFilter
	}
	return filter.Rules()
}

// taggedNames tag nomlariga `tag:` prefiksini qo'shadi.
//
// Operator `--tags web,prod` deb yozadi, ACL da esa `tag:web`
// ko'rinadi. Prefiksni saqlashda qo'shamiz, shunda ACL va registry
// bir xil kalitni ishlatadi va ular ajralib ketmaydi.
func taggedNames(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}

	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if !strings.HasPrefix(tag, "tag:") {
			tag = "tag:" + tag
		}
		out = append(out, tag)
	}
	return out
}
