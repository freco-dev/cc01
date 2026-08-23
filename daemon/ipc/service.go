package ipc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"time"

	"github.com/freco-dev/cc01/daemon/engine"
	"github.com/freco-dev/cc01/daemon/noise"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// Info — demon haqidagi o'zgarmas ma'lumot.
type Info struct {
	NodeID       string
	Hostname     string
	Tenant       string
	Address      string
	ControlPlane string
	Endpoints    []string
	Version      string

	// RelayID — ulangan relay; bo'sh bo'lsa relay yo'q.
	RelayID func() string

	// Routes — marshrut rekonsiliatsiyasining holati. nil bo'lsa
	// (statik rejim) `cc01 doctor` bu tekshiruvni o'tkazib yuboradi.
	Routes RouteStatus
}

// RouteStatus — `route.Reconciler` shu interfeysni qanoatlantiradi.
type RouteStatus interface {
	Synced() bool
	Last() []netip.Prefix
}

// Service — DaemonService implementatsiyasi.
type Service struct {
	cc01v1.UnimplementedDaemonServiceServer

	engine  *engine.Engine
	info    Info
	started time.Time
}

func NewService(datapath *engine.Engine, info Info) *Service {
	return &Service{engine: datapath, info: info, started: time.Now()}
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
	snapshots := s.engine.Snapshot()

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
	checks := RunChecks(s.info.Routes)

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
	peers := s.engine.Snapshot()

	relayID := ""
	if s.info.RelayID != nil {
		relayID = s.info.RelayID()
	}

	key := s.engine.PublicKey()

	return &cc01v1.StatusResponse{
		Connected:     true,
		NodeId:        s.info.NodeID,
		PublicKey:     key.String(),
		Hostname:      s.info.Hostname,
		Tenant:        s.info.Tenant,
		Address:       s.info.Address,
		Interface:     s.engine.InterfaceName(),
		ListenPort:    uint32(s.engine.ListenPort()),
		Endpoints:     s.info.Endpoints,
		ControlPlane:  s.info.ControlPlane,
		RelayId:       relayID,
		PeerCount:     uint32(len(peers)),
		UptimeSeconds: uint64(time.Since(s.started).Seconds()),
		Version:       s.info.Version,
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
