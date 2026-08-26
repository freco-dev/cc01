package cluster

import (
	"context"
	"time"

	"github.com/freco-dev/cc01/control/registry"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Node ro'yxatini o'zgartiruvchi amallar.
//
// Hammasi Raft jurnalidan o'tadi: node ro'yxati faqat liderning
// xotirasida qolsa, failover'dan keyin yangi liderning ro'yxati
// bo'sh bo'lardi va nodelar qayta ro'yxatdan o'tmaguncha
// NetworkMap to'liq bo'lmasdi.
//
// ⚠️ Vaqt va TTL AYNAN SHU YERDA — liderda — hal qilinadi va
// buyruqqa yoziladi. Replikalar faqat qo'llaydi. Aks holda har bir
// replika o'z soatini o'qib, boshqa `ExpiresAt` yozardi.

// RegisterNode nodeni ro'yxatga oladi yoki mavjudini yangilaydi.
func (n *Node) RegisterNode(
	ctx context.Context, reg registry.Registration, ttl time.Duration,
) (*registry.Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

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

	result, err := n.propose(n.now(&cc01v1.LeaseCommand{
		Command: &cc01v1.LeaseCommand_RegisterNode{RegisterNode: cmd},
	}))
	if err != nil {
		return nil, err
	}
	return result.node, result.err
}

// HeartbeatNode TTL ni uzaytiradi va endpointlarni yangilaydi.
//
// `endpoints` nil bo'lsa endpointlarga tegilmaydi; bo'sh ro'yxat
// esa "endpoint qolmadi" degani.
func (n *Node) HeartbeatNode(
	ctx context.Context, nodeID string, endpoints []netipAddrPort, ttl time.Duration,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	cmd := &cc01v1.HeartbeatNode{
		NodeId:       nodeID,
		HasEndpoints: endpoints != nil,
		TtlSeconds:   uint64(ttl / time.Second),
	}
	for _, endpoint := range endpoints {
		cmd.Endpoints = append(cmd.Endpoints, endpoint.String())
	}

	result, err := n.propose(n.now(&cc01v1.LeaseCommand{
		Command: &cc01v1.LeaseCommand_HeartbeatNode{HeartbeatNode: cmd},
	}))
	if err != nil {
		return err
	}
	return result.err
}

// UnregisterNode nodeni ro'yxatdan chiqaradi.
func (n *Node) UnregisterNode(ctx context.Context, nodeID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	result, err := n.propose(n.now(&cc01v1.LeaseCommand{
		Command: &cc01v1.LeaseCommand_UnregisterNode{
			UnregisterNode: &cc01v1.UnregisterNode{NodeId: nodeID},
		},
	}))
	if err != nil {
		return err
	}
	return result.err
}

// ExpireNodes muddati o'tganlarni chiqaradi va nechtasi
// chiqarilganini qaytaradi.
func (n *Node) ExpireNodes(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	result, err := n.propose(n.now(&cc01v1.LeaseCommand{
		Command: &cc01v1.LeaseCommand_ExpireNodes{ExpireNodes: &cc01v1.ExpireNodes{}},
	}))
	if err != nil {
		return 0, err
	}
	return result.reclaimed, result.err
}

// now buyruqqa liderning vaqtini yozadi.
func (n *Node) now(cmd *cc01v1.LeaseCommand) *cc01v1.LeaseCommand {
	cmd.Now = timestamppb.New(time.Now())
	return cmd
}
