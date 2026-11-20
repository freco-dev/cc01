package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// TCPServer bitta listener ustidagi Accept sikli.
//
// Start va Stop odatda turli goroutine'larda ishlaydi (tunnel yopilishi
// Accept sikli davom etayotganda Stop ni chaqiradi), shuning uchun
// listener maydoni mx ostida: Start uni bir marta oladi, Stop esa uni
// yopadi va "to'xtatilgan" deb belgilaydi — Accept sikli hech qachon
// nil listener'ga murojaat qilmaydi.
type TCPServer struct {
	title string

	mx       sync.Mutex
	listener net.Listener // mx ostida; Stop dan keyin nil
}

// acceptRetryMax — vaqtinchalik Accept xatosidan (masalan, EMFILE —
// fayl deskriptorlari tugagan) keyingi eng uzun pauza. Bunday xato
// listener'ni abadiy o'chirib qo'ymasligi kerak.
const acceptRetryMax = time.Second

func (s *TCPServer) Init(port uint16, title string) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	s.title = title
	s.mx.Lock()
	s.listener = ln
	s.mx.Unlock()
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
	s.mx.Lock()
	s.listener = ln
	s.mx.Unlock()
	return nil
}

func (s *TCPServer) Start(handler func(conn net.Conn) error) {
	// Listener BIR MARTA olinadi: Stop uni yopsa Accept net.ErrClosed
	// qaytaradi va sikl tugaydi.
	s.mx.Lock()
	ln := s.listener
	s.mx.Unlock()
	if ln == nil {
		return
	}

	var retry time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Vaqtinchalik xato: kutib, qayta urinamiz.
			retry = min(max(2*retry, 5*time.Millisecond), acceptRetryMax)
			log.Printf("[%s]: accept: %v (%s dan keyin qayta urinish)\n", s.title, err, retry)
			time.Sleep(retry)
			continue
		}
		retry = 0
		go func() {
			err := handler(conn)
			if err != nil {
				log.Printf("[%s]: %s\n", s.title, err.Error())
			}
		}()
	}
}

// Stop listener'ni yopadi. Qayta chaqirish xavfsiz; Stop dan keyin
// Port() 0 qaytaradi.
func (s *TCPServer) Stop() error {
	s.mx.Lock()
	ln := s.listener
	s.listener = nil
	s.mx.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Close()
}

func (s *TCPServer) Port() uint16 {
	s.mx.Lock()
	defer s.mx.Unlock()
	if s.listener == nil {
		return 0
	}
	return uint16(s.listener.Addr().(*net.TCPAddr).Port)
}
