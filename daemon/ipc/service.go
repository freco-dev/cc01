package ipc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/freco-dev/cc01/daemon/engine"
	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/route"
	"github.com/freco-dev/cc01/daemon/session"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Backend — IPC xizmati ma'lumotni shundan oladi va buyruqlarni
// shunga uzatadi.
//
// Interfeys sifatida ajratilgan, chunki `cc01 up`/`down` dan keyin
// datapath demon jarayonidan qisqaroq umr ko'radi: xizmat aniq bir
// engine'ga emas, uni yaratib-yo'q qiladigan qatlamga bog'lanishi
// kerak.
type Backend interface {
	// Status — joriy holat. false — mesh tushirilgan.
	Status() (session.Status, bool)

	// Peers — datapath ko'rayotgan peerlar.
	Peers() []engine.PeerSnapshot

	Up(ctx context.Context) error
	Down() error
}

// Service — DaemonService implementatsiyasi.
type Service struct {
	cc01v1.UnimplementedDaemonServiceServer

	backend Backend
	version string
}

func NewService(backend Backend, version string) *Service {
	return &Service{backend: backend, version: version}
}

func (s *Service) Status(context.Context, *cc01v1.StatusRequest) (*cc01v1.StatusResponse, error) {
	return s.snapshot(), nil
}

// WatchStatus holatni davriy yuboradi.
//
// O'zgarish bo'yicha emas, davriy: holatning ko'p qismi (RTT, sessiya
// yoshi) uzluksiz o'zgaradi, ya'ni "o'zgarish" hodisasi ma'noga ega
// emas.
func (s *Service) WatchStatus(
	req *cc01v1.WatchStatusRequest,
	stream cc01v1.DaemonService_WatchStatusServer,
) error {
	interval := time.Duration(req.GetIntervalSeconds()) * time.Second
	if interval <= 0 {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Birinchi holatni darhol yuboramiz — klient kutmasligi kerak.
	if err := stream.Send(&cc01v1.WatchStatusResponse{Status: s.snapshot()}); err != nil {
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			if err := stream.Send(&cc01v1.WatchStatusResponse{Status: s.snapshot()}); err != nil {
				return err
			}
		}
	}
}

func (s *Service) Peers(_ context.Context, req *cc01v1.PeersRequest) (*cc01v1.PeersResponse, error) {
	snapshots := s.backend.Peers()

	out := &cc01v1.PeersResponse{Peers: make([]*cc01v1.PeerStatus, 0, len(snapshots))}
	for _, peer := range snapshots {
		if req.GetOnlineOnly() && !peer.Online {
			continue
		}
		out.Peers = append(out.Peers, toProtoPeer(peer))
	}

	return out, nil
}

func (s *Service) Doctor(context.Context, *cc01v1.DoctorRequest) (*cc01v1.DoctorResponse, error) {
	// Mesh tushirilgan bo'lsa marshrut holati haqida gapiradigan
	// narsa yo'q — bo'lmagan narsa haqida "hammasi joyida" deb
	// yozgandan ko'ra, umuman yozmagan yaxshi.
	var routes *route.Status
	if snapshot, up := s.backend.Status(); up {
		routes = &snapshot.Routes
	}

	checks := RunChecks(routes)

	out := &cc01v1.DoctorResponse{
		Checks:  make([]*cc01v1.Check, 0, len(checks)),
		Healthy: true,
	}

	for _, check := range checks {
		if check.Status == cc01v1.Check_STATUS_FAIL {
			out.Healthy = false
		}
		out.Checks = append(out.Checks, check)
	}

	return out, nil
}

func (s *Service) snapshot() *cc01v1.StatusResponse {
	current, up := s.backend.Status()
	if !up {
		// Tushirilgan mesh ham javob beradi: `cc01 status` demon
		// ishlayotganini, lekin ulanmaganini ko'rsatishi kerak.
		return &cc01v1.StatusResponse{Connected: false, Version: s.version}
	}

	return &cc01v1.StatusResponse{
		Connected:     true,
		NodeId:        current.NodeID,
		PublicKey:     current.PublicKey.String(),
		Hostname:      current.Hostname,
		Tenant:        current.Tenant,
		Address:       current.Address,
		Interface:     current.Interface,
		ListenPort:    uint32(current.ListenPort),
		Endpoints:     current.Endpoints,
		ControlPlane:  current.ControlPlane,
		RelayId:       current.RelayID,
		PeerCount:     uint32(len(s.backend.Peers())),
		UptimeSeconds: uint64(time.Since(current.Since).Seconds()),
		Version:       s.version,
	}
}

func toProtoPeer(peer engine.PeerSnapshot) *cc01v1.PeerStatus {
	out := &cc01v1.PeerStatus{
		NodeId:            nodeIDFor(peer.PublicKey),
		PublicKey:         peer.PublicKey.String(),
		Path:              peer.Path.String(),
		PathState:         peer.State.String(),
		Online:            peer.Online,
		RttMicros:         uint64(peer.RTT.Microseconds()),
		SessionAgeSeconds: uint64(peer.SessionAge.Seconds()),
	}

	if peer.Endpoint.IsValid() {
		out.Endpoint = peer.Endpoint.String()
	}

	out.Addresses = make([]string, 0, len(peer.AllowedIPs))
	for _, prefix := range peer.AllowedIPs {
		out.Addresses = append(out.Addresses, prefix.String())
	}

	return out
}

// nodeIDFor public kalitdan node_id hisoblaydi
// (ARCHITECTURE.md §3.1.2).
func nodeIDFor(key noise.PublicKey) string {
	sum := sha256.Sum256(key[:])
	return hex.EncodeToString(sum[:])
}

// Up mesh'ni ko'taradi.
//
// Allaqachon ko'tarilgan bo'lsa ALREADY_EXISTS qaytariladi (§5.2 dagi
// exit kod 12): buyruq bajarilmadi va foydalanuvchi buni bilishi kerak.
func (s *Service) Up(ctx context.Context, _ *cc01v1.UpRequest) (*cc01v1.UpResponse, error) {
	if err := s.backend.Up(ctx); err != nil {
		if errors.Is(err, session.ErrAlreadyUp) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &cc01v1.UpResponse{Status: s.snapshot()}, nil
}

// Down mesh'ni tushiradi.
//
// Allaqachon tushirilgan bo'lsa xato EMAS: "tushirilgan bo'lsin"
// degan talab allaqachon bajarilgan. Foydalanuvchi buni javobdagi
// bayroqdan biladi.
func (s *Service) Down(context.Context, *cc01v1.DownRequest) (*cc01v1.DownResponse, error) {
	if _, up := s.backend.Status(); !up {
		return &cc01v1.DownResponse{AlreadyDown: true}, nil
	}

	if err := s.backend.Down(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &cc01v1.DownResponse{}, nil
}
