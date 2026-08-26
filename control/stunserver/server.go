// Package stunserver minimal STUN binding serverini beradi
// (RFC 5389, ARCHITECTURE.md §3.1.4).
//
// Vazifasi bitta: so'ragan tomonga uning KO'RINGAN manzilini aytish.
// NAT ortidagi node o'zining public manzilini boshqa yo'l bilan bila
// olmaydi — lokal interfeysdagi manzil tashqaridan erishib bo'lmaydi.
//
// Server holatsiz: har bir so'rov mustaqil, hech narsa saqlanmaydi.
// Shu sababli uni anycast orqasida ixtiyoriy PoP'da ko'paytirish mumkin.
package stunserver

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	pion "github.com/pion/stun/v3"
)

// DefaultPort — RFC 5389 belgilagan STUN porti.
const DefaultPort = 3478

// Server — UDP ustidagi STUN binding serveri.
type Server struct {
	socket *net.UDPConn
	log    *slog.Logger

	closeOnce sync.Once
	closed    chan struct{}
	done      chan struct{}
}

// Listen berilgan manzilda server ochadi.
func Listen(address string, logger *slog.Logger) (*Server, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("stunserver: manzil (%s): %w", address, err)
	}

	socket, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("stunserver: tinglash (%s): %w", address, err)
	}

	if logger == nil {
		logger = slog.Default()
	}

	return &Server{
		socket: socket,
		log:    logger.With("component", "stun"),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}, nil
}

// Addr — server tinglayotgan manzil.
func (s *Server) Addr() netip.AddrPort {
	udpAddr, ok := s.socket.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	return udpAddr.AddrPort()
}

// Serve so'rovlarni qayta ishlaydi. Close chaqirilguncha bloklaydi.
func (s *Server) Serve() {
	defer close(s.done)

	buf := make([]byte, 1500)

	for {
		n, from, err := s.socket.ReadFromUDPAddrPort(buf)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Debug("o'qish xatosi", "err", err)
			continue
		}

		s.respond(buf[:n], from)
	}
}

func (s *Server) respond(payload []byte, from netip.AddrPort) {
	if !pion.IsMessage(payload) {
		// STUN bo'lmagan paketlar jimgina tashlanadi: port skanerlash
		// va shovqin odatiy hol.
		return
	}

	request := &pion.Message{Raw: append([]byte(nil), payload...)}
	if err := request.Decode(); err != nil {
		return
	}

	if request.Type != pion.BindingRequest {
		return
	}

	// Javobning butun ma'nosi shu: so'ragan tomon o'zini QANDAY
	// ko'rinishini biladi. NAT manzil va portni almashtirgan bo'lsa,
	// bu yerda aynan almashtirilgani qaytadi.
	response, err := pion.Build(
		request,
		pion.BindingSuccess,
		&pion.XORMappedAddress{
			IP:   net.IP(from.Addr().AsSlice()),
			Port: int(from.Port()),
		},
		pion.Fingerprint,
	)
	if err != nil {
		s.log.Debug("javob qurilmadi", "err", err)
		return
	}

	if _, err := s.socket.WriteToUDPAddrPort(response.Raw, from); err != nil {
		s.log.Debug("javob yuborilmadi", "to", from, "err", err)
	}
}

// Close serverni to'xtatadi va Serve tugashini kutadi.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.closed)
		err = s.socket.Close()
		<-s.done
	})
	return err
}
