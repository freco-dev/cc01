package main

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/freco-dev/cc01/core-server/config"
	"github.com/freco-dev/cc01/core-server/events"
	"github.com/freco-dev/cc01/core-server/server"
	"github.com/freco-dev/cc01/core-server/tunnel"
)

const dateFormat = "2006/01/02 15:04:05"
const defaultSubdomain = "cc01"

type CC01Server struct {
	config          config.Config
	eventServer     server.TCPServer
	publicServer    server.TCPServer
	publicServerTLS server.TCPServer
	cnameMap        map[string]string
	tcpTunnels      map[uint16]*tunnel.TCPTunnel
	httpTunnels     map[string]*tunnel.HTTPTunnel
}

func (j *CC01Server) Init(conf config.Config) error {
	j.config = conf
	j.cnameMap = make(map[string]string)
	j.tcpTunnels = make(map[uint16]*tunnel.TCPTunnel)
	j.httpTunnels = make(map[string]*tunnel.HTTPTunnel)

	if err := j.eventServer.Init(conf.EventServerPort, "cc01_event_server"); err != nil {
		return err
	}
	if err := j.publicServer.Init(conf.PublicServerPort, "cc01_public_server"); err != nil {
		return err
	}
	err := j.publicServerTLS.InitTLS(conf.PublicServerTLSPort, "cc01_public_server_tls", conf.TLSCertFile, conf.TLSKeyFile)
	return err
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
	err := j.publicServerTLS.Stop()
	return err
}

func (j *CC01Server) servePublicConn(conn net.Conn) error {
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	host, buffer, err := parseHost(conn)
	if err != nil || host == "" {
		writeResponse(conn, 400, "Bad Request", "Bad Request")
		return nil
	}
	if tunnelHost, ok := j.cnameMap[host]; ok && tunnelHost != "" {
		host = tunnelHost
	}
	host = strings.ToLower(host)
	t, found := j.httpTunnels[host]
	if !found {
		writeResponse(conn, 404, "Not Found", "tunnel not found")
		return fmt.Errorf("unknown host requested %s", host)
	}
	return t.PublicConnectionHandler(conn, buffer)
}

func (j *CC01Server) serveEventConn(conn net.Conn) error {
	defer conn.Close()

	var event events.Event[events.TunnelRequested]
	if err := event.Read(conn); err != nil {
		return err
	}

	request := event.Data
	if request.Protocol != events.HTTP && request.Protocol != events.TCP {
		return events.WriteError(conn, "invalid protocol %s", request.Protocol)
	}

	if request.Subdomain == "" {
		request.Subdomain = defaultSubdomain
	}
	if err := validate(&request.Subdomain); err != nil {
		return events.WriteError(conn, "invalid subdomain %s: %s", request.Subdomain, err.Error())
	}
	hostname := fmt.Sprintf("%s.%s", request.Subdomain, j.config.DomainName)
	if _, ok := j.httpTunnels[hostname]; ok {
		return events.WriteError(conn, "subdomain is busy: %s, try another one", request.Subdomain)
	}
	cname := request.CanonName
	if _, ok := j.cnameMap[cname]; ok && cname != "" {
		return events.WriteError(conn, "cname is busy: %s, try another one", request.CanonName)
	}

	var t tunnel.Tunnel
	var maxConsLimit = j.config.MaxConsPerTunnel

	switch request.Protocol {
	case events.HTTP:
		tn, err := tunnel.NewHTTP(hostname, conn, maxConsLimit)
		if err != nil {
			return events.WriteError(conn, "failed to create http tunnel", err.Error())
		}
		j.cnameMap[cname] = hostname
		j.httpTunnels[hostname] = tn
		defer delete(j.cnameMap, cname)
		defer delete(j.httpTunnels, hostname)
		t = tn
	case events.TCP:
		tn, err := tunnel.NewTCP(hostname, conn, maxConsLimit)
		if err != nil {
			return events.WriteError(conn, "failed to create tcp tunnel", err.Error())
		}
		j.tcpTunnels[tn.PublicServerPort()] = tn
		defer delete(j.tcpTunnels, tn.PublicServerPort())
		t = tn
	}

	tunnelId := fmt.Sprintf("%s:%d", t.Hostname(), t.PublicServerPort())

	t.Open()
	defer t.Close()
	opened := events.Event[events.TunnelOpened]{
		Data: &events.TunnelOpened{
			Hostname:      t.Hostname(),
			Protocol:      t.Protocol(),
			PublicServer:  t.PublicServerPort(),
			PrivateServer: t.PrivateServerPort(),
		},
	}
	if err := opened.Write(conn); err != nil {
		return err
	}

	fmt.Printf("%s [tunnel-opened] %s\n", time.Now().Format(dateFormat), tunnelId)

	buffer := make([]byte, 8) // wait until connection is closed
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Minute))
		if _, err := conn.Read(buffer); err == io.EOF {
			break
		}
	}
	fmt.Printf("%s [tunnel-closed] %s\n", time.Now().Format(dateFormat), tunnelId)
	return nil
}
