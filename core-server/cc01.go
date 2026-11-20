package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/freco-dev/cc01/core-server/access"
	"github.com/freco-dev/cc01/core-server/config"
	"github.com/freco-dev/cc01/core-server/events"
	"github.com/freco-dev/cc01/core-server/server"
	"github.com/freco-dev/cc01/core-server/tlsmgr"
	"github.com/freco-dev/cc01/core-server/tunnel"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

const dateFormat = "2006/01/02 15:04:05"
const defaultSubdomain = "cc01"

type CC01Server struct {
	config          config.Config
	authorizer      access.Authorizer
	eventServer     server.TCPServer
	publicServer    server.TCPServer
	publicServerTLS server.TCPServer
	tunnelsMx       sync.RWMutex
	cnameMap        map[string]string
	tcpTunnels      map[uint16]*tunnel.TCPTunnel
	httpTunnels     map[string]*tunnel.HTTPTunnel

	// tenantTunnels — shu edge'dagi har bir tenantning ochiq tunnellari
	// soni (max_tunnels faqat ochilishda tekshiriladi). Faqat sonlar:
	// limitlarning o'zi har tunnelning o'z goroutine'ida yashaydi.
	// tunnelsMx ostida; TenantID "" (AllowAll) hisoblanmaydi.
	tenantTunnels map[string]int

	certs *tlsmgr.Resolver

	// logOut — tunnel hodisalari log'i ([tunnel-opened], [tunnel-limits]
	// va h.k.). nil — os.Stdout; testlar o'z yozuvchisini beradi.
	logOut io.Writer
}

func (j *CC01Server) Init(conf config.Config) error {
	j.config = conf

	if err := j.initAuthorizer(); err != nil {
		return err
	}

	j.initRegistry()

	if err := j.eventServer.Init(conf.EventServerPort, "cc01_event_server"); err != nil {
		return err
	}
	if err := j.publicServer.Init(conf.PublicServerPort, "cc01_public_server"); err != nil {
		return err
	}
	tlsConfig, err := j.buildTLS()
	if err != nil {
		return err
	}
	return j.publicServerTLS.InitTLS(conf.PublicServerTLSPort, "cc01_public_server_tls", tlsConfig)
}

// initRegistry tunnel ro'yxatlarini yaratadi.
func (j *CC01Server) initRegistry() {
	j.cnameMap = make(map[string]string)
	j.tcpTunnels = make(map[uint16]*tunnel.TCPTunnel)
	j.httpTunnels = make(map[string]*tunnel.HTTPTunnel)
	j.tenantTunnels = make(map[string]int)
}

// logf tunnel hodisasini vaqt belgisi bilan yozadi.
//
// ⚠️ Token hech qachon log'ga tushmasligi kerak: chaqiruvchilar faqat
// tunnel ID, tenant, tarif va xato kodini uzatadi.
func (j *CC01Server) logf(format string, args ...any) {
	out := j.logOut
	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintf(out, "%s "+format+"\n", append([]any{time.Now().Format(dateFormat)}, args...)...)
}

// buildTLS SNI bo'yicha sertifikat tanlaydigan sozlamani quradi.
func (j *CC01Server) buildTLS() (*tls.Config, error) {
	wildcard, err := tls.LoadX509KeyPair(j.config.TLSCertFile, j.config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("wildcard sertifikat: %w", err)
	}

	var acme *tlsmgr.ACME
	if j.config.ACMEEnabled() {
		acme, err = tlsmgr.NewACME(tlsmgr.ACMEOptions{
			Email:     j.config.ACMEEmail,
			Directory: j.config.ACMEDirectory,
			CA:        j.config.ACMECA,
			Decide:    j.knownDomain,
		})
		if err != nil {
			return nil, err
		}
		log.Printf("ACME yoqilgan: custom domainlar avtomatik sertifikat oladi (%s)",
			j.config.ACMEDirectory)
	} else {
		log.Printf("⚠️  ACME o'chiq (CC01_ACME_EMAIL berilmagan): " +
			"custom domainlar HTTPS ola olmaydi")
	}

	resolver, err := tlsmgr.New(tlsmgr.Options{
		Domain:   j.config.DomainName,
		Wildcard: &wildcard,
		Apex:     &wildcard,
		Known:    j.knownDomain,
		Issuer:   issuerOrNil(acme),
	})
	if err != nil {
		return nil, err
	}
	j.certs = resolver

	return tlsmgr.TLSConfig(resolver, acme), nil
}

// issuerOrNil nil `*ACME` ni nil interfeysga aylantiradi.
//
// Usiz `Issuer` interfeysi nil ko'rsatkichni o'rab, "nil emas"
// bo'lib qolardi va resolver mavjud bo'lmagan chiqaruvchiga
// murojaat qilardi.
func issuerOrNil(acme *tlsmgr.ACME) tlsmgr.Issuer {
	if acme == nil {
		return nil
	}
	return acme
}

// knownDomain — bu custom domenga hozir tunnel ochilganmi.
//
// ⚠️ Sertifikat FAQAT tirik tunnel uchun beriladi. Har qanday
// SNI ga sertifikat chiqarsak, kimdir o'z domenining DNS'ini
// bizga qaratib, ACME limitlarini yoqib yuborardi.
//
// Egalik bu yerda tekshirilmaydi — u access-server tomonida,
// tunnel ochilishidan oldin hal qilingan.
func (j *CC01Server) knownDomain(name string) bool {
	j.tunnelsMx.RLock()
	defer j.tunnelsMx.RUnlock()

	host, ok := j.cnameMap[name]
	return ok && host != ""
}

func (j *CC01Server) initAuthorizer() error {
	if j.config.AuthMode == config.AuthDisabled {
		log.Printf("⚠️  AVTORIZATSIYA O'CHIRILGAN (CC01_AUTH_MODE=disabled). " +
			"Har qanday token qabul qilinadi va subdomain egaligi tekshirilmaydi. " +
			"Bu rejim faqat lokal ishlab chiqish uchun.")

		j.authorizer = &access.AllowAll{
			Limits: access.Grant{
				Plan:              "disabled",
				MaxConnsPerTunnel: j.config.MaxConsPerTunnel,
				MaxTunnels:        1,
			},
		}
		return nil
	}

	client, err := access.Dial(access.Options{
		Address: j.config.AccessAddr,
		Timeout: j.config.AccessTimeout,
		Grace:   j.config.AccessGrace,
		// Kesh yangiligi yangilash oralig'i bilan cheklanadi: aks holda
		// keshdan ochilgan tunnel AP'dagi o'zgarishni LeaseTTL qadar
		// kechikib ko'rardi. 0 (yangilash o'chiq) — chegara yo'q.
		MaxFresh: j.config.AccessRenew,
		// mTLS (DEV_SPEC S-11); nil — shifrsiz, config uni faqat loopback
		// manzil uchun ruxsat etadi.
		TLS: j.config.AccessTLS,
	})
	if err != nil {
		return err
	}

	if info := j.config.AccessTLSInfo; info != nil {
		log.Printf("[access] mTLS: CA=%s, CN=%s, server_name=%s, TLS ≥ %s, sertifikat muddati %s "+
			"(almashtirish uchun qayta ishga tushirish kerak)",
			info.CAFile, info.ClientCN, info.ServerName, info.MinVersion,
			info.ClientNotAfter.UTC().Format(time.RFC3339))
		if info.MinVersion != "1.3" {
			log.Printf("[access] ⚠ TLS 1.2 ruxsat etilgan (CC01_ACCESS_TLS_MIN=%s) — faqat loopback dev uchun",
				info.MinVersion)
		}
	} else {
		log.Printf("[access] plaintext (loopback): %s", j.config.AccessAddr)
	}

	log.Printf("avtorizatsiya: access-server %s (grace %s)",
		j.config.AccessAddr, j.config.AccessGrace)
	if j.config.AccessRenew > 0 {
		log.Printf("ochiq tunnellar har ≤%s da qayta tekshiriladi (rad javobida: %s)",
			j.config.AccessRenew, j.config.AccessRenewDeny)
	} else {
		log.Printf("⚠️  ochiq tunnellarni qayta tekshirish O'CHIQ (CC01_ACCESS_RENEW=0): " +
			"tarif o'zgarishi va bekor qilish faqat yangi tunnellarga ta'sir qiladi")
	}

	j.authorizer = client
	return nil
}

func (j *CC01Server) Start() {
	go j.eventServer.Start(j.serveEventConn)
	go j.publicServer.Start(j.servePublicConn)
	go j.publicServerTLS.Start(j.servePublicConn)
}

func (j *CC01Server) Stop() error {
	if err := j.eventServer.Stop(); err != nil {
		return err
	}
	if err := j.publicServer.Stop(); err != nil {
		return err
	}
	if err := j.publicServerTLS.Stop(); err != nil {
		return err
	}
	if j.authorizer != nil {
		return j.authorizer.Close()
	}
	return nil
}

// publicHostTimeout — ommaviy ulanishdan Host sarlavhasini (TLS'da qo'l
// siqishni ham) o'qish va 400/404 javobini yozish uchun muddat.
const publicHostTimeout = 3 * time.Second

func (j *CC01Server) servePublicConn(conn net.Conn) error {
	// Muddat FAQAT Host aniqlanguncha amal qiladi: ko'prikka ulangan
	// ulanishda u qolib ketsa, Bind 3 s dan keyin o'qishda timeout olib,
	// sekin javob, katta yuklama, SSE/WebSocket va keep-alive'ni uzardi.
	_ = conn.SetDeadline(time.Now().Add(publicHostTimeout))
	host, buffer, err := parseHost(conn)
	if err != nil || host == "" {
		writeResponse(conn, 400, "Bad Request", "Bad Request")
		return nil
	}
	host = normalizeHost(host)

	j.tunnelsMx.RLock()
	if tunnelHost, ok := j.cnameMap[host]; ok && tunnelHost != "" {
		host = tunnelHost
	}
	t, found := j.httpTunnels[host]
	j.tunnelsMx.RUnlock()
	if !found {
		writeResponse(conn, 404, "Not Found", "tunnel not found")
		return fmt.Errorf("unknown host requested %s", host)
	}
	_ = conn.SetDeadline(time.Time{})
	return t.PublicConnectionHandler(conn, buffer)
}

func (j *CC01Server) serveEventConn(conn net.Conn) error {
	defer conn.Close()

	// Preambula: eski gob klienti bu tekshiruvdan o'ta olmaydi va aniq
	// xato oladi — noto'g'ri parse qilingan baytlar bilan ishlamaymiz.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := events.ReadPreamble(conn); err != nil {
		return fmt.Errorf("preambula: %w", err)
	}

	frame, err := events.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("tunnel so'rovi: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	request := frame.GetTunnelRequested()
	if request == nil {
		return eventError(conn, "PROTOCOL_ERROR",
			"birinchi freym TunnelRequested bo'lishi kerak")
	}

	switch request.GetProtocol() {
	case cc01v1.Protocol_PROTOCOL_HTTP, cc01v1.Protocol_PROTOCOL_TCP:
	default:
		return eventError(conn, "PROTOCOL_INVALID",
			"protokol qo'llab-quvvatlanmaydi: %s", request.GetProtocol())
	}

	// Subdomain va limitlar access-server tomonidan hal qilinadi — edge
	// o'zi qaror qabul qilmaydi. Faqat format tekshiruvi shu yerda qoladi,
	// chunki u yaroqsiz so'rovni tarmoqqa chiqarmasdan to'sadi.
	subdomain := request.GetSubdomain()
	if subdomain != "" {
		if err := validate(&subdomain); err != nil {
			return eventError(conn, "SUBDOMAIN_INVALID",
				"subdomain yaroqsiz (%s): %s", subdomain, err.Error())
		}
	}

	// Asl so'rov saqlanadi: yangilashlar xuddi shu token va protokol bilan,
	// lekin BERILGAN subdomain bilan yuboriladi (renew.go).
	authReq := access.Request{
		Token:        request.GetToken(),
		Protocol:     protocolName(request.GetProtocol()),
		Subdomain:    subdomain,
		CustomDomain: request.GetCustomDomain(),
		CliVersion:   request.GetCliVersion(),
		ClientIP:     clientIP(conn),
	}
	grant, err := j.authorizer.Authorize(context.Background(), authReq)
	if err != nil {
		var denial *access.Denial
		if errors.As(err, &denial) {
			return eventError(conn, denial.Code, "%s", denial.Message)
		}
		// Tarmoq xatosi va kesh'da yaroqli yozuv yo'q — deny-by-default.
		return eventError(conn, "SERVICE_UNAVAILABLE",
			"avtorizatsiya xizmati javob bermadi, keyinroq urinib ko'ring")
	}

	// Yakuniy nom access-server'dan keladi: klient bo'sh qoldirgan bo'lsa
	// u hisobdagi mavjud subdomainni tanlaydi.
	subdomain = grant.Subdomain
	if subdomain == "" {
		subdomain = defaultSubdomain
	}

	hostname := fmt.Sprintf("%s.%s", subdomain, j.config.DomainName)
	cname := request.GetCustomDomain()

	// Oldindan tekshiruv — listener ochmasdan rad etish uchun. Yakuniy
	// qaror pastda, ro'yxatga yozish bilan bitta qulf ostida.
	j.tunnelsMx.Lock()
	if _, ok := j.httpTunnels[hostname]; ok {
		j.tunnelsMx.Unlock()
		return eventError(conn, "SUBDOMAIN_BUSY", "subdomain band: %s", subdomain)
	}
	if _, ok := j.cnameMap[cname]; ok && cname != "" {
		j.tunnelsMx.Unlock()
		return eventError(conn, "DOMAIN_BUSY", "domen band: %s", cname)
	}
	if j.tenantAtLimit(grant) {
		j.tunnelsMx.Unlock()
		return tunnelQuotaError(conn, grant)
	}
	j.tunnelsMx.Unlock()

	var (
		t          tunnel.Tunnel
		publicPort uint16
	)

	// Tarif limiti qattiq yozilgan qiymatning o'rnini bosadi.
	maxConsLimit := j.effectiveMaxConns(grant)

	switch request.GetProtocol() {
	case cc01v1.Protocol_PROTOCOL_HTTP:
		tn, err := tunnel.NewHTTP(hostname, conn, maxConsLimit)
		if err != nil {
			tn.Close()
			return eventError(conn, "TUNNEL_CREATE_FAILED",
				"http tunnel yaratilmadi: %s", err.Error())
		}
		j.tunnelsMx.Lock()
		if _, ok := j.httpTunnels[hostname]; ok {
			j.tunnelsMx.Unlock()
			tn.Close()
			return eventError(conn, "SUBDOMAIN_BUSY", "subdomain band: %s", subdomain)
		}
		if _, ok := j.cnameMap[cname]; ok && cname != "" {
			j.tunnelsMx.Unlock()
			tn.Close()
			return eventError(conn, "DOMAIN_BUSY", "domen band: %s", cname)
		}
		if j.tenantAtLimit(grant) {
			j.tunnelsMx.Unlock()
			tn.Close()
			return tunnelQuotaError(conn, grant)
		}
		if cname != "" {
			j.cnameMap[cname] = hostname
		}
		j.httpTunnels[hostname] = tn
		j.acquireTenant(grant.TenantID)
		j.tunnelsMx.Unlock()
		defer func() {
			j.tunnelsMx.Lock()
			if cname != "" {
				delete(j.cnameMap, cname)
			}
			delete(j.httpTunnels, hostname)
			j.releaseTenant(grant.TenantID)
			j.tunnelsMx.Unlock()

			// Sertifikat keshi tozalanmaydi — resolver umuman
			// keshlamaydi va ruxsatni har bir qo'l siqishida
			// qaytadan tekshiradi. Ya'ni cnameMap dan o'chirish
			// bilan sertifikat berish darhol to'xtaydi.
		}()
		t = tn
		publicPort = tn.PublicServerPort()

	case cc01v1.Protocol_PROTOCOL_TCP:
		tn, err := tunnel.NewTCP(hostname, conn, maxConsLimit)
		if err != nil {
			tn.Close()
			return eventError(conn, "TUNNEL_CREATE_FAILED",
				"tcp tunnel yaratilmadi: %s", err.Error())
		}
		// Port HOZIR olinadi: Close() dan keyin listener yo'q va
		// PublicServerPort() 0 qaytaradi — ro'yxatdan o'chirish boshqa
		// kalit bilan urinib, yozuvni abadiy qoldirardi.
		port := tn.PublicServerPort()
		j.tunnelsMx.Lock()
		if j.tenantAtLimit(grant) {
			j.tunnelsMx.Unlock()
			tn.Close()
			return tunnelQuotaError(conn, grant)
		}
		j.tcpTunnels[port] = tn
		j.acquireTenant(grant.TenantID)
		j.tunnelsMx.Unlock()
		defer func() {
			j.tunnelsMx.Lock()
			delete(j.tcpTunnels, port)
			j.releaseTenant(grant.TenantID)
			j.tunnelsMx.Unlock()
		}()
		t = tn
		publicPort = port
	}

	tunnelID := fmt.Sprintf("%s:%d", t.Hostname(), publicPort)
	// Boshqaruv kanali t.Close() DAN OLDIN yopiladi: kanalga yozib turib
	// qolgan goroutine (o'qimay qo'ygan klient) darhol bo'shaydi va
	// yuqoridagi ro'yxatdan o'chirish defer'lari albatta ishlaydi.
	defer func() {
		_ = conn.Close()
		t.Close()
	}()

	// TunnelOpened Open() dan OLDIN yuboriladi: listenerlar Init'da
	// ochilgan, ulanishlar navbatda kutadi. Yozish muvaffaqiyatsiz bo'lsa
	// Accept goroutine'lari umuman ishga tushmaydi.
	if err := t.WriteOpened(&cc01v1.TunnelOpened{
		Hostname:    t.Hostname(),
		Protocol:    request.GetProtocol(),
		PublicPort:  uint32(publicPort),
		PrivatePort: uint32(t.PrivateServerPort()),
		TunnelId:    tunnelID,
	}); err != nil {
		return err
	}
	t.Open()

	j.logf("[tunnel-opened] %s tenant=%s plan=%s max_conns=%d",
		tunnelID, grant.TenantID, grant.Plan, maxConsLimit)

	// Klient bu kanalga hech narsa yozmaydi; har qanday o'qish xatosi
	// (EOF, reset, yopilgan ulanish) — u ketganini bildiradi. Deadline
	// yo'q: kutish faqat shu goroutine'da, aylanib qolmaydi.
	//
	// Klient ketishi bilan kanal shu yerda yopiladi: yarim yopilgan
	// (SHUT_WR) va o'qimayotgan klient tufayli kanalga yozishda turib
	// qolgan goroutine yozish muddatini kutmasdan bo'shaydi.
	clientGone := make(chan struct{})
	go func() {
		defer close(clientGone)
		defer conn.Close()
		buffer := make([]byte, 512)
		for {
			if _, err := conn.Read(buffer); err != nil {
				return
			}
		}
	}()

	denial := j.superviseTunnel(context.Background(), t, t.Notify,
		authReq, grant, tunnelID, clientGone)

	j.logf("[tunnel-closed] %s", tunnelID)
	if denial != nil {
		return fmt.Errorf("tunnel yopildi (%s): %w", tunnelID, denial)
	}
	return nil
}

// effectiveMaxConns — tunnelga qo'llanadigan ulanish limiti: tarifdan,
// tarif bermagan bo'lsa sozlamadagi zaxira qiymat.
func (j *CC01Server) effectiveMaxConns(g *access.Grant) int {
	if g.MaxConnsPerTunnel > 0 {
		return g.MaxConnsPerTunnel
	}
	return j.config.MaxConsPerTunnel
}

// tenantAtLimit — tenant shu edge'da max_tunnels ga yetganmi.
// Chaqiruvchi tunnelsMx ni ushlab turadi. TenantID "" (AllowAll) va
// MaxTunnels <= 0 cheklanmaydi.
func (j *CC01Server) tenantAtLimit(g *access.Grant) bool {
	return g.TenantID != "" && g.MaxTunnels > 0 &&
		j.tenantTunnels[g.TenantID] >= g.MaxTunnels
}

// acquireTenant va releaseTenant tunnelsMx ostida chaqiriladi.
func (j *CC01Server) acquireTenant(tenantID string) {
	if tenantID != "" {
		j.tenantTunnels[tenantID]++
	}
}

func (j *CC01Server) releaseTenant(tenantID string) {
	if tenantID == "" {
		return
	}
	if n := j.tenantTunnels[tenantID] - 1; n > 0 {
		j.tenantTunnels[tenantID] = n
	} else {
		delete(j.tenantTunnels, tenantID)
	}
}

// eventError rad javobini boshqaruv kanaliga yozish muddati bilan
// yuboradi: o'qimayotgan klient serveEventConn ni ushlab tura olmaydi.
// Tunnel ochilgandan keyingi freymlar tunnel ichida xuddi shunday
// muddat bilan yoziladi (tunnel.EventWriteTimeout).
func eventError(conn net.Conn, code, format string, args ...any) error {
	_ = conn.SetWriteDeadline(time.Now().Add(tunnel.EventWriteTimeout))
	return events.WriteError(conn, code, format, args...)
}

func tunnelQuotaError(conn net.Conn, g *access.Grant) error {
	return eventError(conn, "QUOTA_TUNNELS_EXCEEDED",
		"bir vaqtda ochiq tunnellar limiti tugadi: tarif (%s) %d ta tunnelga ruxsat beradi",
		g.Plan, g.MaxTunnels)
}

func protocolName(p cc01v1.Protocol) string {
	switch p {
	case cc01v1.Protocol_PROTOCOL_HTTP:
		return "http"
	case cc01v1.Protocol_PROTOCOL_TCP:
		return "tcp"
	default:
		return ""
	}
}

// clientIP audit va rate limit uchun — avtorizatsiya qaroriga ta'sir
// qilmaydi, shuning uchun aniqlab bo'lmasa bo'sh qoldiriladi.
func clientIP(conn net.Conn) string {
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return ""
	}
	return addr.IP.String()
}
