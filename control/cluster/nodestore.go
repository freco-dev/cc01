package cluster

import (
	"context"
	"net/netip"
	"time"

	"github.com/freco-dev/cc01/control/registry"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NodeStore — node ro'yxatini o'zgartirish yo'li.
//
// Servis registry'ni TO'G'RIDAN-TO'G'RI o'zgartirmaydi: klasterda
// o'zgarish jurnaldan o'tishi shart, aks holda u faqat bitta
// replikada qolib, failover'da yo'qolardi.
type NodeStore interface {
	RegisterNode(ctx context.Context, reg registry.Registration, ttl time.Duration) (*registry.Node, error)
	HeartbeatNode(ctx context.Context, nodeID string, endpoints []netip.AddrPort, ttl time.Duration) error
	UnregisterNode(ctx context.Context, nodeID string) error
	ExpireNodes(ctx context.Context) (int, error)
}

// MemoryNodes — klastersiz rejim uchun.
//
// Buyruqlar AYNAN o'sha protobuf shaklidan o'tadi va o'sha
// `registry.Apply` ni chaqiradi. Alohida yo'l yozsak, klastersiz
// rejim boshqacha tekshiruvlar bilan ishlab, klasterga o'tganda
// kutilmagan xatolar chiqardi.
type MemoryNodes struct {
	registry *registry.Registry
}

func NewMemoryNodes(nodes *registry.Registry) *MemoryNodes {
	return &MemoryNodes{registry: nodes}
}

func (m *MemoryNodes) RegisterNode(
	_ context.Context, reg registry.Registration, ttl time.Duration,
) (*registry.Node, error) {
	cmd := &cc01v1.RegisterNode{
		PublicKey:  reg.PublicKey[:],
		Tenant:     reg.Tenant,
		Hostname:   reg.Hostname,
		Tags:       reg.Tags,
		RelayHome:  reg.RelayHome,
		TtlSeconds: uint64(ttl / time.Second),
	}
	for _, prefix := range reg.Addresses {
		cmd.Addresses = append(cmd.Addresses, prefix.String())
	}
	for _, endpoint := range reg.Endpoints {
		cmd.Endpoints = append(cmd.Endpoints, endpoint.String())
	}

	node, _, err := m.registry.Apply(&cc01v1.LeaseCommand{
		Now:     timestamppb.New(time.Now()),
		Command: &cc01v1.LeaseCommand_RegisterNode{RegisterNode: cmd},
	})
	return node, err
}

func (m *MemoryNodes) HeartbeatNode(
	_ context.Context, nodeID string, endpoints []netip.AddrPort, ttl time.Duration,
) error {
	cmd := &cc01v1.HeartbeatNode{
		NodeId:       nodeID,
		HasEndpoints: endpoints != nil,
		TtlSeconds:   uint64(ttl / time.Second),
	}
	for _, endpoint := range endpoints {
		cmd.Endpoints = append(cmd.Endpoints, endpoint.String())
	}

	_, _, err := m.registry.Apply(&cc01v1.LeaseCommand{
		Now:     timestamppb.New(time.Now()),
		Command: &cc01v1.LeaseCommand_HeartbeatNode{HeartbeatNode: cmd},
	})
	return err
}

func (m *MemoryNodes) UnregisterNode(_ context.Context, nodeID string) error {
	_, _, err := m.registry.Apply(&cc01v1.LeaseCommand{
		Now: timestamppb.New(time.Now()),
		Command: &cc01v1.LeaseCommand_UnregisterNode{
			UnregisterNode: &cc01v1.UnregisterNode{NodeId: nodeID},
		},
	})
	return err
}

func (m *MemoryNodes) ExpireNodes(_ context.Context) (int, error) {
	_, expired, err := m.registry.Apply(&cc01v1.LeaseCommand{
		Now:     timestamppb.New(time.Now()),
		Command: &cc01v1.LeaseCommand_ExpireNodes{ExpireNodes: &cc01v1.ExpireNodes{}},
	})
	return expired, err
}

var (
	_ NodeStore = (*MemoryNodes)(nil)
	_ NodeStore = (*Node)(nil)
)
