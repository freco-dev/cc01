package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	certs           *tlsmgr.Resolver
}

func (j *CC01Server) Init(conf config.Config) error {
	j.config = conf

	if err := j.initAuthorizer(); err != nil {
		return err
	}

	j.cnameMap = make(map[string]string)
	j.tcpTunnels = make(map[uint16]*tunnel.TCPTunnel)
	j.httpTunnels = make(map[string]*tunnel.HTTPTunnel)

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
	})
	if err != nil {
		return err
	}

	log.Printf("avtorizatsiya: access-server %s (grace %s)",
		j.config.AccessAddr, j.config.AccessGrace)

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

func (j *CC01Server) servePublicConn(conn net.Conn) error {
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
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
		return events.WriteError(conn, "PROTOCOL_ERROR",
			"birinchi freym TunnelRequested bo'lishi kerak")
	}

	switch request.GetProtocol() {
	case cc01v1.Protocol_PROTOCOL_HTTP, cc01v1.Protocol_PROTOCOL_TCP:
	default:
		return events.WriteError(conn, "PROTOCOL_INVALID",
			"protokol qo'llab-quvvatlanmaydi: %s", request.GetProtocol())
	}

	// Subdomain va limitlar access-server tomonidan hal qilinadi — edge
	// o'zi qaror qabul qilmaydi. Faqat format tekshiruvi shu yerda qoladi,
	// chunki u yaroqsiz so'rovni tarmoqqa chiqarmasdan to'sadi.
	subdomain := request.GetSubdomain()
	if subdomain != "" {
		if err := validate(&subdomain); err != nil {
			return events.WriteError(conn, "SUBDOMAIN_INVALID",
				"subdomain yaroqsiz (%s): %s", subdomain, err.Error())
		}
	}

	grant, err := j.authorizer.Authorize(context.Background(), access.Request{
		Token:        request.GetToken(),
		Protocol:     protocolName(request.GetProtocol()),
		Subdomain:    subdomain,
		CustomDomain: request.GetCustomDomain(),
		CliVersion:   request.GetCliVersion(),
		ClientIP:     clientIP(conn),
	})
	if err != nil {
		var denial *access.Denial
		if errors.As(err, &denial) {
			return events.WriteError(conn, denial.Code, "%s", denial.Message)
		}
		// Tarmoq xatosi va kesh'da yaroqli yozuv yo'q — deny-by-default.
		return events.WriteError(conn, "SERVICE_UNAVAILABLE",
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

	j.tunnelsMx.Lock()
	if _, ok := j.httpTunnels[hostname]; ok {
		j.tunnelsMx.Unlock()
		return events.WriteError(conn, "SUBDOMAIN_BUSY", "subdomain band: %s", subdomain)
	}
	if _, ok := j.cnameMap[cname]; ok && cname != "" {
		j.tunnelsMx.Unlock()
		return events.WriteError(conn, "DOMAIN_BUSY", "domen band: %s", cname)
	}
	j.tunnelsMx.Unlock()

	var t tunnel.Tunnel

	// Tarif limiti qattiq yozilgan qiymatning o'rnini bosadi.
	maxConsLimit := grant.MaxConnsPerTunnel
	if maxConsLimit <= 0 {
		maxConsLimit = j.config.MaxConsPerTunnel
	}

	switch request.GetProtocol() {
	case cc01v1.Protocol_PROTOCOL_HTTP:
		tn, err := tunnel.NewHTTP(hostname, conn, maxConsLimit)
		if err != nil {
			return events.WriteError(conn, "TUNNEL_CREATE_FAILED",
				"http tunnel yaratilmadi: %s", err.Error())
		}
		j.tunnelsMx.Lock()
		if _, ok := j.httpTunnels[hostname]; ok {
			j.tunnelsMx.Unlock()
			tn.Close()
			return events.WriteError(conn, "SUBDOMAIN_BUSY", "subdomain band: %s", subdomain)
		}
		if _, ok := j.cnameMap[cname]; ok && cname != "" {
			j.tunnelsMx.Unlock()
			tn.Close()
			return events.WriteError(conn, "DOMAIN_BUSY", "domen band: %s", cname)
		}
		if cname != "" {
			j.cnameMap[cname] = hostname
		}
		j.httpTunnels[hostname] = tn
		j.tunnelsMx.Unlock()
		defer func() {
			j.tunnelsMx.Lock()
			if cname != "" {
				delete(j.cnameMap, cname)
			}
			delete(j.httpTunnels, hostname)
			j.tunnelsMx.Unlock()

			// Sertifikat keshi tozalanmaydi — resolver umuman
			// keshlamaydi va ruxsatni har bir qo'l siqishida
			// qaytadan tekshiradi. Ya'ni cnameMap dan o'chirish
			// bilan sertifikat berish darhol to'xtaydi.
		}()
		t = tn

	case cc01v1.Protocol_PROTOCOL_TCP:
		tn, err := tunnel.NewTCP(hostname, conn, maxConsLimit)
		if err != nil {
			return events.WriteError(conn, "TUNNEL_CREATE_FAILED",
				"tcp tunnel yaratilmadi: %s", err.Error())
		}
		j.tunnelsMx.Lock()
		j.tcpTunnels[tn.PublicServerPort()] = tn
		j.tunnelsMx.Unlock()
		defer func() {
			j.tunnelsMx.Lock()
			delete(j.tcpTunnels, tn.PublicServerPort())
			j.tunnelsMx.Unlock()
		}()
		t = tn
	}

	tunnelID := fmt.Sprintf("%s:%d", t.Hostname(), t.PublicServerPort())

	t.Open()
	defer t.Close()

	if err := events.WriteTunnelOpened(conn, &cc01v1.TunnelOpened{
		Hostname:    t.Hostname(),
		Protocol:    request.GetProtocol(),
		PublicPort:  uint32(t.PublicServerPort()),
		PrivatePort: uint32(t.PrivateServerPort()),
		TunnelId:    tunnelID,
	}); err != nil {
		return err
	}

	fmt.Printf("%s [tunnel-opened] %s tenant=%s plan=%s max_conns=%d\n",
		time.Now().Format(dateFormat), tunnelID, grant.TenantID, grant.Plan, maxConsLimit)

	// Ulanish yopilguncha kutamiz. Klient bu kanalga hech narsa yozmaydi;
	// EOF — u ketganini bildiradi.
	buffer := make([]byte, 8)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Minute))
		if _, err := conn.Read(buffer); err == io.EOF {
			break
		}
	}
	fmt.Printf("%s [tunnel-closed] %s\n", time.Now().Format(dateFormat), tunnelID)
	return nil
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
