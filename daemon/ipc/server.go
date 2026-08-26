// Package ipc demonni mahalliy CLI uchun ochadi (DEV_SPEC §5.2).
//
// Transport — UNIX domain socket. Tarmoq orqali ochilmaydi: bu
// mahalliy boshqaruv interfeysi, va uni tarmoqqa chiqarish demonni
// masofadan boshqarish imkonini berardi.
//
// Autentifikatsiya soket ruxsatlariga tayanadi (0660): faqat egasi va
// belgilangan guruh a'zolari ulana oladi. Demon `CAP_NET_ADMIN` bilan
// ishlaydi, ya'ni bu soketga kirish demonning imtiyozlariga kirish
// bilan teng.
package ipc

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc"
)

// Registrar qo'shimcha gRPC xizmatini ro'yxatga oladi.
type Registrar func(*grpc.Server)

// WithFirewall firewall xizmatini qo'shadi.
func WithFirewall(provider FirewallProvider) Registrar {
	return func(server *grpc.Server) {
		cc01v1.RegisterFirewallServiceServer(server, NewFirewallService(provider))
	}
}

// DefaultSocket — standart soket yo'li (DEV_SPEC §5.2).
const DefaultSocket = "/run/cc01/cc01.sock"

// SocketMode — soket ruxsatlari: egasi va guruh o'qiy/yoza oladi,
// boshqalar yo'q.
const SocketMode os.FileMode = 0o660

// Server — demon IPC serveri.
type Server struct {
	socket   string
	listener net.Listener
	grpc     *grpc.Server
	log      *slog.Logger

	closeOnce sync.Once
}

// Listen soketni ochadi va servisni ro'yxatga oladi.
//
// Mavjud soket fayli o'chiriladi: demon SIGKILL bilan tugagan bo'lsa
// u orqada qolishi mumkin (DEV_SPEC §7.1 majburiy stsenariy 8).
func Listen(
	socket string,
	service cc01v1.DaemonServiceServer,
	logger *slog.Logger,
	extra ...Registrar,
) (*Server, error) {
	if socket == "" {
		socket = DefaultSocket
	}
	if logger == nil {
		logger = slog.Default()
	}

	// UNIX soketi yo'li yadro tuzilmasidagi maydonga sig'ishi kerak.
	// Sig'masa yadro `invalid argument` qaytaradi — bu xato sababni
	// umuman ko'rsatmaydi, shuning uchun oldindan tekshiramiz.
	if len(socket) > maxSocketPath {
		return nil, fmt.Errorf(
			"ipc: soket yo'li juda uzun: %d belgi, chegara %d\n  qisqaroq yo'l tanlang, masalan %s",
			len(socket), maxSocketPath, DefaultSocket)
	}

	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil {
		return nil, fmt.Errorf("ipc: papka yaratish: %w", err)
	}

	// Eski soketni tozalaymiz. Faqat SOKET faylini o'chiramiz —
	// boshqa turdagi faylni o'chirish xavfli bo'lardi.
	if info, err := os.Stat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("ipc: %s soket emas", socket)
		}
		if err := os.Remove(socket); err != nil {
			return nil, fmt.Errorf("ipc: eski soketni o'chirish: %w", err)
		}
	}

	listener, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("ipc: tinglash (%s): %w", socket, err)
	}

	if err := os.Chmod(socket, SocketMode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("ipc: ruxsatlarni o'rnatish: %w", err)
	}

	// Guruh yo'qligi halokatli emas — konteynerda yoki paketsiz
	// o'rnatishda u bo'lmasligi normal. Bunda soket root:root bo'lib
	// qoladi va faqat root ulana oladi; buni jimgina qoldirmaymiz,
	// chunki foydalanuvchi keyin "ruxsat yo'q" xatosini ko'radi.
	if err := applyOwnership(socket, DefaultGroup); err != nil {
		if errors.Is(err, errGroupMissing) {
			logger.Info("soket guruhi yo'q, faqat root ulana oladi",
				"group", DefaultGroup, "socket", socket)
		} else {
			logger.Warn("soket egaligini o'rnatib bo'lmadi", "err", err)
		}
	}

	grpcServer := grpc.NewServer()
	cc01v1.RegisterDaemonServiceServer(grpcServer, service)

	// Qo'shimcha xizmatlar (masalan firewall) ixtiyoriy: eBPF
	// mavjud bo'lmagan muhitda demon ularsiz ham ishlashi kerak.
	for _, register := range extra {
		register(grpcServer)
	}

	return &Server{
		socket:   socket,
		listener: listener,
		grpc:     grpcServer,
		log:      logger.With("component", "ipc"),
	}, nil
}

// Socket — ochilgan soket yo'li.
func (s *Server) Socket() string { return s.socket }

// Serve so'rovlarni qayta ishlaydi. Close chaqirilguncha bloklaydi.
func (s *Server) Serve() error {
	s.log.Info("IPC tayyor", "socket", s.socket)

	if err := s.grpc.Serve(s.listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// Close serverni to'xtatadi va soket faylini tozalaydi.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.grpc.GracefulStop()
		// Soket faylini ortda qoldirmaymiz: keyingi ishga tushishda
		// u "band" bo'lib ko'rinardi.
		err = os.Remove(s.socket)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	})
	return err
}

// Dial CLI tomonidan chaqiriladi.
func Dial(socket string) (*grpc.ClientConn, error) {
	if socket == "" {
		socket = DefaultSocket
	}

	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecureCreds()))
	if err != nil {
		return nil, fmt.Errorf("ipc: ulanish (%s): %w", socket, err)
	}
	return conn, nil
}
