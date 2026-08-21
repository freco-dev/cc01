package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/freco-dev/cc01/core-server/events"
	cc01v1 "github.com/freco-dev/cc01/core-server/gen/cc01/v1"
)

const cliVersion = "dev"

type config struct {
	serverAddr string
	localAddr  string
	protocol   string
	subdomain  string
	cname      string
	token      string
}

func main() {
	conf := parseFlags()
	if err := run(conf); err != nil {
		log.Fatal(err)
	}
}

func parseFlags() config {
	conf := config{}
	flag.StringVar(&conf.serverAddr, "server", "127.0.0.1:4321", "cc01 event server address")
	flag.StringVar(&conf.localAddr, "local", "127.0.0.1:8080", "local service address")
	flag.StringVar(&conf.protocol, "proto", "http", "tunnel protocol: http or tcp")
	flag.StringVar(&conf.subdomain, "subdomain", "", "requested public subdomain")
	flag.StringVar(&conf.cname, "cname", "", "optional custom domain (CNAME)")
	flag.StringVar(&conf.token, "token", os.Getenv("CC01_TOKEN"),
		"API token (yoki CC01_TOKEN muhit o'zgaruvchisi)")
	flag.Parse()

	conf.protocol = strings.ToLower(strings.TrimSpace(conf.protocol))
	conf.token = strings.TrimSpace(conf.token)
	return conf
}

func run(conf config) error {
	protocol, err := parseProtocol(conf.protocol)
	if err != nil {
		return err
	}

	control, err := net.Dial("tcp", conf.serverAddr)
	if err != nil {
		return fmt.Errorf("event serverga ulanish: %w", err)
	}
	defer control.Close()

	if err := events.WritePreamble(control); err != nil {
		return fmt.Errorf("preambula yuborish: %w", err)
	}

	if err := events.WriteTunnelRequested(control, &cc01v1.TunnelRequested{
		Protocol:     protocol,
		Subdomain:    conf.subdomain,
		CustomDomain: conf.cname,
		Token:        conf.token,
		CliVersion:   cliVersion,
	}); err != nil {
		return fmt.Errorf("tunnel so'rovini yuborish: %w", err)
	}

	frame, err := events.ReadFrame(control)
	if err != nil {
		return fmt.Errorf("javobni o'qish: %w", err)
	}

	opened := frame.GetTunnelOpened()
	if opened == nil {
		return errors.New("kutilmagan javob: TunnelOpened emas")
	}
	if opened.GetErrorMessage() != "" {
		// Kod mashina uchun, xabar odam uchun.
		return fmt.Errorf("%s: %s", opened.GetErrorCode(), opened.GetErrorMessage())
	}

	serverHost, err := hostFromAddr(conf.serverAddr)
	if err != nil {
		return err
	}

	printTunnelInfo(opened, conf.localAddr)
	return serveTunnel(control, serverHost, conf.localAddr, uint16(opened.GetPrivatePort()))
}

func parseProtocol(raw string) (cc01v1.Protocol, error) {
	switch raw {
	case "http":
		return cc01v1.Protocol_PROTOCOL_HTTP, nil
	case "tcp":
		return cc01v1.Protocol_PROTOCOL_TCP, nil
	default:
		return cc01v1.Protocol_PROTOCOL_UNSPECIFIED,
			fmt.Errorf("protokol qo'llab-quvvatlanmaydi: %q (http yoki tcp)", raw)
	}
}

func serveTunnel(control net.Conn, serverHost, localAddr string, privatePort uint16) error {
	var wg sync.WaitGroup
	for {
		frame, err := events.ReadFrame(control)
		if err != nil {
			wg.Wait()
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return fmt.Errorf("hodisani o'qish: %w", err)
		}

		received := frame.GetConnectionReceived()
		if received == nil {
			// Kelajakdagi freym turlari eski klientni yiqitmasligi kerak.
			continue
		}

		if received.GetRateLimited() {
			log.Printf("ulanish rad etildi (limit): %s", net.IP(received.GetClientIp()))
			continue
		}

		wg.Add(1)
		go func(clientPort uint16) {
			defer wg.Done()
			if err := bridgeConnection(serverHost, privatePort, localAddr, clientPort); err != nil {
				log.Printf("ulanishni ko'prikda bog'lash muvaffaqiyatsiz: %v", err)
			}
		}(uint16(received.GetClientPort()))
	}
}

func bridgeConnection(serverHost string, privatePort uint16, localAddr string, clientPort uint16) error {
	privateAddr := net.JoinHostPort(serverHost, fmt.Sprintf("%d", privatePort))
	privateConn, err := net.Dial("tcp", privateAddr)
	if err != nil {
		return fmt.Errorf("connect private tunnel %s: %w", privateAddr, err)
	}
	defer privateConn.Close()

	portBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBytes, clientPort)
	if _, err := privateConn.Write(portBytes); err != nil {
		return fmt.Errorf("send connection id: %w", err)
	}

	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("connect local service %s: %w", localAddr, err)
	}
	defer localConn.Close()

	bind(privateConn, localConn)
	return nil
}

func bind(a net.Conn, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}

	go func() {
		_, _ = io.Copy(a, b)
		once.Do(closeBoth)
	}()
	_, _ = io.Copy(b, a)
	once.Do(closeBoth)
}

func hostFromAddr(addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("server address must be host:port: %w", err)
	}
	if host == "" {
		return "127.0.0.1", nil
	}
	return host, nil
}

func printTunnelInfo(opened *cc01v1.TunnelOpened, localAddr string) {
	switch opened.GetProtocol() {
	case cc01v1.Protocol_PROTOCOL_HTTP:
		fmt.Fprintf(os.Stdout, "HTTP tunnel ochildi: http://%s -> %s\n",
			opened.GetHostname(), localAddr)
	case cc01v1.Protocol_PROTOCOL_TCP:
		fmt.Fprintf(os.Stdout, "TCP tunnel ochildi: %s:%d -> %s\n",
			opened.GetHostname(), opened.GetPublicPort(), localAddr)
	default:
		fmt.Fprintf(os.Stdout, "Tunnel ochildi: %s:%d -> %s\n",
			opened.GetHostname(), opened.GetPublicPort(), localAddr)
	}
}
