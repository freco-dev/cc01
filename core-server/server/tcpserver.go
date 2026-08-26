package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
)

type TCPServer struct {
	title    string
	listener net.Listener
}

func (s *TCPServer) Init(port uint16, title string) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	s.title = title
	s.listener = ln
	return nil
}

// InitTLS TLS listener ochadi.
//
// Sertifikat FAYLDAN emas, `config.GetCertificate` orqali
// tanlanadi: edge bir vaqtda wildcard subdomainlarga ham, custom
// domainlarga ham xizmat qiladi va qaysi biri kerakligi faqat
// SNI dan ma'lum bo'ladi (DEV_SPEC §2.1 `tlsmgr`).
func (s *TCPServer) InitTLS(port uint16, title string, config *tls.Config) error {
	if config == nil || config.GetCertificate == nil {
		return errors.New("tls: sertifikat tanlovchi berilmagan")
	}

	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), config)
	if err != nil {
		return err
	}
	s.title = title
	s.listener = ln
	return nil
}

func (s *TCPServer) Start(handler func(conn net.Conn) error) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go func() {
			err := handler(conn)
			if err != nil {
				log.Printf("[%s]: %s\n", s.title, err.Error())
			}
		}()
	}
}

func (s *TCPServer) Stop() error {
	if s.listener == nil {
		return nil
	}
	err := s.listener.Close()
	s.listener = nil
	return err
}

func (s *TCPServer) Port() uint16 {
	if s.listener == nil {
		return 0
	}
	return uint16(s.listener.Addr().(*net.TCPAddr).Port)
}
