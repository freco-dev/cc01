// Package server Control Plane ni gRPC orqali oshkor qiladi.
//
// Registry va IPAM ni birlashtiradi: node ro'yxatdan o'tganda unga
// manzil beriladi, keyin u NetworkMap stream'iga ulanadi va
// peerlarni avtomatik oladi.
package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/freco-dev/cc01/control/cluster"
	"github.com/freco-dev/cc01/control/ipam"
	"github.com/freco-dev/cc01/control/registry"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config — servis sozlamalari.
type Config struct {
	Registry  *registry.Registry
	Allocator *ipam.Allocator

	// TenantPrefix — nodelarga manzil beriladigan segment.
	// Faza 1 da bitta tenant; ko'p tenantli taqsimlash `cc01-idp`
	// bilan keladi.
	TenantPrefix netip.Prefix

	// AuthToken — bo'sh bo'lsa autentifikatsiya O'CHIRILGAN.
	// Chaqiruvchi buni oshkora tanlashi kerak (ARCHITECTURE.md §1.5:
	// deny-by-default).
	AuthToken string

	// Identities — nodelarni sertifikatlariga bog'laydi. nil bo'lsa
	// xotiradagi ombor ishlatiladi.
	Identities cluster.IdentityStore

	Logger *slog.Logger
}

// Service — ControlService gRPC implementatsiyasi.
type Service struct {
	cc01v1.UnimplementedControlServiceServer

	registry   *registry.Registry
	allocator  *ipam.Allocator
	identities cluster.IdentityStore
	tenantNet  netip.Prefix
	authToken  string
	log        *slog.Logger
}

// HeartbeatInterval — klient qanchalik tez-tez xabar berishi kerak.
//
// Registry TTL'idan (90 s) uch barobar kichik: ikkita xabar yo'qolsa
// ham node ro'yxatdan tushib qolmaydi.
const HeartbeatInterval = 30 * time.Second

func New(cfg Config) (*Service, error) {
	if cfg.Registry == nil {
		return nil, errors.New("cp: registry berilmagan")
	}
	if cfg.Allocator == nil {
		return nil, errors.New("cp: allocator berilmagan")
	}
	if !cfg.TenantPrefix.IsValid() {
		return nil, errors.New("cp: tenant prefiksi berilmagan")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	identities := cfg.Identities
	if identities == nil {
		// Klastersiz rejim: bog'lanishlar jarayon umriga bog'liq.
		identities = cluster.NewMemoryIdentities()
	}

	return &Service{
		registry:   cfg.Registry,
		allocator:  cfg.Allocator,
		identities: identities,
		tenantNet:  cfg.TenantPrefix.Masked(),
		authToken:  cfg.AuthToken,
		log:        logger.With("component", "cp"),
	}, nil
}

// authorize oldindan kelishilgan sirni tekshiradi.
//
// Bu vaqtinchalik: haqiqiy yechim — node sertifikatlari va mTLS
// (ARCHITECTURE.md §3.1.1). Sir bo'sh bo'lsa tekshiruv o'tkazib
// yuboriladi, lekin server ishga tushganda ogohlantirish chiqaradi.
func (s *Service) authorize(token string) error {
	if s.authToken == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.authToken)) != 1 {
		return status.Error(codes.Unauthenticated, "noto'g'ri auth token")
	}
	return nil
}

// Register nodeni ro'yxatga oladi va unga IPv6 manzil beradi.
func (s *Service) Register(
	ctx context.Context,
	req *cc01v1.RegisterRequest,
) (*cc01v1.RegisterResponse, error) {
	// Kalit uzunligi AVVAL tekshiriladi: node_id undan hosil
	// qilinadi va autentifikatsiya o'shanga tayanadi.
	if len(req.GetPublicKey()) != 32 {
		return nil, status.Errorf(codes.InvalidArgument,
			"public kalit 32 bayt bo'lishi kerak, %d olindi", len(req.GetPublicKey()))
	}

	var key registry.PublicKey
	copy(key[:], req.GetPublicKey())
	nodeID := registry.NodeID(key)

	if err := s.authenticate(ctx, nodeID, req.GetAuthToken()); err != nil {
		return nil, err
	}
	if req.GetTenant() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant ko'rsatilmagan")
	}

	// Manzil AVVAL beriladi: registry yozuvida `addresses` bo'lishi
	// kerak, aks holda peerlar uni allowed_ips siz ko'rardi.
	lease, err := s.allocator.Allocate(ctx, ipam.Request{
		Kind:      ipam.KindNode,
		Owner:     nodeID,
		Tenant:    req.GetTenant(),
		Parent:    s.tenantNet,
		PrefixLen: 128,
		Preferred: parsePrefix(req.GetPreferredAddress()),
	})
	if err != nil {
		s.log.Error("manzil berilmadi", "node", nodeID, "err", err)
		// Klasterda yozuvni faqat lider bajara oladi. Xatoni
		// ResourceExhausted deb yubormaymiz — u "pool to'ldi"
		// degani bo'lib, operatorni butunlay boshqa tomonga
		// yo'naltirardi.
		var notLeader *cluster.ErrNotLeader
		if errors.As(err, &notLeader) {
			return nil, status.Errorf(codes.Unavailable,
				"bu node lider emas; %s ga murojaat qiling", notLeader.Leader)
		}

		return nil, status.Errorf(codes.ResourceExhausted, "manzil berilmadi: %v", err)
	}

	endpoints, err := parseEndpoints(req.GetEndpoints())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "endpoint: %v", err)
	}

	node, err := s.registry.Register(registry.Registration{
		PublicKey: key,
		Tenant:    req.GetTenant(),
		Hostname:  req.GetHostname(),
		Addresses: []netip.Prefix{lease.Prefix},
		Endpoints: endpoints,
		Tags:      req.GetTags(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ro'yxatga olish: %v", err)
	}

	s.log.Info("node ro'yxatdan o'tdi",
		"node", node.ID[:12], "hostname", node.Hostname,
		"address", lease.Prefix, "tenant", node.Tenant)

	return &cc01v1.RegisterResponse{
		NodeId:             node.ID,
		Address:            lease.Prefix.String(),
		TenantCidr:         s.tenantNet.String(),
		LeaseId:            lease.ID,
		LeaseExpiresAt:     lease.ExpiresAt.Unix(),
		HeartbeatIntervalS: uint32(HeartbeatInterval.Seconds()),
	}, nil
}

// Heartbeat ijarani va ro'yxatdagi holatni uzaytiradi.
func (s *Service) Heartbeat(
	ctx context.Context,
	req *cc01v1.HeartbeatRequest,
) (*cc01v1.HeartbeatResponse, error) {
	if err := s.authenticate(ctx, req.GetNodeId(), req.GetAuthToken()); err != nil {
		return nil, err
	}

	endpoints, err := parseEndpoints(req.GetEndpoints())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "endpoint: %v", err)
	}

	if err := s.registry.Heartbeat(req.GetNodeId(), endpoints); err != nil {
		if errors.Is(err, registry.ErrNodeNotFound) {
			// Node ro'yxatdan tushib qolgan — qayta ro'yxatdan
			// o'tishi kerak.
			return nil, status.Error(codes.NotFound, "node ro'yxatda yo'q, qayta ro'yxatdan o'ting")
		}
		return nil, status.Errorf(codes.Internal, "heartbeat: %v", err)
	}

	var expiresAt int64
	if node, ok := s.registry.Node(req.GetNodeId()); ok {
		expiresAt = node.ExpiresAt.Unix()
	}

	_ = ctx
	return &cc01v1.HeartbeatResponse{
		LeaseExpiresAt: expiresAt,
		MapVersion:     s.registry.Version(),
	}, nil
}

// WatchNetworkMap uzun yashovchi stream: birinchi javob to'liq map,
// keyin har bir o'zgarishda delta.
func (s *Service) WatchNetworkMap(
	req *cc01v1.WatchNetworkMapRequest,
	stream cc01v1.ControlService_WatchNetworkMapServer,
) error {
	if err := s.authenticate(stream.Context(), req.GetNodeId(), req.GetAuthToken()); err != nil {
		return err
	}

	node, ok := s.registry.Node(req.GetNodeId())
	if !ok {
		return status.Error(codes.NotFound, "node ro'yxatda yo'q")
	}

	ctx := stream.Context()

	// Kuzatuvchini birinchi mapdan OLDIN ro'yxatga olamiz, aks holda
	// oradagi o'zgarish yo'qolib ketardi.
	updates := s.registry.Watch(ctx, node.Tenant)

	since := req.GetSince()
	if err := s.sendMap(stream, node.ID, &since); err != nil {
		return err
	}

	s.log.Debug("NetworkMap stream ochildi", "node", node.ID[:12], "tenant", node.Tenant)

	for {
		select {
		case <-ctx.Done():
			return nil

		case _, open := <-updates:
			if !open {
				return nil
			}
			if err := s.sendMap(stream, node.ID, &since); err != nil {
				return err
			}
		}
	}
}

// sendMap mapni quradi va yuboradi; bo'sh delta yuborilmaydi.
func (s *Service) sendMap(
	stream cc01v1.ControlService_WatchNetworkMapServer,
	nodeID string,
	since *uint64,
) error {
	netmap, err := s.registry.NetworkMapFor(nodeID, *since)
	if err != nil {
		if errors.Is(err, registry.ErrNodeNotFound) {
			return status.Error(codes.NotFound, "node ro'yxatdan chiqarildi")
		}
		return status.Errorf(codes.Internal, "netmap: %v", err)
	}

	// Bo'sh delta yuborishning ma'nosi yo'q — tarmoqni behuda
	// band qilmaymiz.
	if netmap.Empty() {
		*since = netmap.Version
		return nil
	}

	if err := stream.Send(toProtoMap(netmap)); err != nil {
		return err
	}

	*since = netmap.Version
	return nil
}

func parseEndpoints(raw []string) ([]netip.AddrPort, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	endpoints := make([]netip.AddrPort, 0, len(raw))
	for _, item := range raw {
		addr, err := netip.ParseAddrPort(item)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", item, err)
		}
		endpoints = append(endpoints, addr)
	}
	return endpoints, nil
}

func parsePrefix(raw string) netip.Prefix {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}
	}
	return prefix
}
