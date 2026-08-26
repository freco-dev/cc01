package registry

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// ErrBadCommand — buyruq o'qib bo'lmaydigan yoki to'liq emas.
var ErrBadCommand = errors.New("registry: buyruq yaroqsiz")

// Apply — holatni o'zgartirishning YAGONA yo'li.
//
// Registry Raft holat mashinasining bir qismi: uni to'g'ridan-to'g'ri
// o'zgartirish faqat bitta replikaga ta'sir qilardi va failover'dan
// keyin o'sha o'zgarish yo'qolardi. Shuning uchun o'zgartiruvchi
// metodlar eksport qilinmagan — ular faqat shu yerdan chaqiriladi.
//
// ⚠️ TO'LIQ DETERMINISTIK bo'lishi shart: vaqt, TTL va tartib —
// hammasi buyruqdan keladi. Bu yerda `time.Now()` ni o'qish yoki
// map bo'ylab saralanmagan yurish replikalarni ajratib yuborardi.
func (r *Registry) Apply(cmd *cc01v1.LeaseCommand) (*Node, int, error) {
	if cmd == nil {
		return nil, 0, fmt.Errorf("%w: bo'sh", ErrBadCommand)
	}

	now := cmd.GetNow().AsTime()

	switch body := cmd.GetCommand().(type) {
	case *cc01v1.LeaseCommand_RegisterNode:
		node, err := r.applyRegisterCmd(body.RegisterNode, now)
		return node, 0, err

	case *cc01v1.LeaseCommand_HeartbeatNode:
		return nil, 0, r.applyHeartbeatCmd(body.HeartbeatNode, now)

	case *cc01v1.LeaseCommand_UnregisterNode:
		return nil, 0, r.applyUnregister(body.UnregisterNode.GetNodeId())

	case *cc01v1.LeaseCommand_ExpireNodes:
		return nil, r.applyExpire(now), nil

	default:
		return nil, 0, fmt.Errorf("%w: turi noma'lum", ErrBadCommand)
	}
}

// Handles — buyruq registry'ga tegishlimi.
//
// FSM bitta jurnaldan o'qiydi va yozuvni kimga berishni shu yerdan
// biladi. Tekshiruvni FSM ichida yozsak, yangi buyruq qo'shilganda
// uni ikki joyda yangilash kerak bo'lardi.
func Handles(cmd *cc01v1.LeaseCommand) bool {
	switch cmd.GetCommand().(type) {
	case *cc01v1.LeaseCommand_RegisterNode,
		*cc01v1.LeaseCommand_HeartbeatNode,
		*cc01v1.LeaseCommand_UnregisterNode,
		*cc01v1.LeaseCommand_ExpireNodes:
		return true
	default:
		return false
	}
}

func (r *Registry) applyRegisterCmd(cmd *cc01v1.RegisterNode, now time.Time) (*Node, error) {
	if len(cmd.GetPublicKey()) != len(PublicKey{}) {
		return nil, fmt.Errorf("%w: kalit uzunligi %d", ErrBadCommand, len(cmd.GetPublicKey()))
	}

	var key PublicKey
	copy(key[:], cmd.GetPublicKey())

	addresses, err := parsePrefixes(cmd.GetAddresses())
	if err != nil {
		return nil, err
	}
	endpoints, err := parseAddrPorts(cmd.GetEndpoints())
	if err != nil {
		return nil, err
	}

	ttl, err := commandTTL(cmd.GetTtlSeconds())
	if err != nil {
		return nil, err
	}

	return r.applyRegister(now, ttl, Registration{
		PublicKey: key,
		Tenant:    cmd.GetTenant(),
		Hostname:  cmd.GetHostname(),
		Addresses: addresses,
		Endpoints: endpoints,
		Tags:      cmd.GetTags(),
		RelayHome: cmd.GetRelayHome(),
	})
}

func (r *Registry) applyHeartbeatCmd(cmd *cc01v1.HeartbeatNode, now time.Time) error {
	ttl, err := commandTTL(cmd.GetTtlSeconds())
	if err != nil {
		return err
	}

	// nil va bo'sh ro'yxat FARQ QILADI: birinchisi "endpointlarga
	// tegmang", ikkinchisi "endpoint qolmadi". Protobuf ularni
	// ajratmaydi, shuning uchun alohida bayroq bor.
	var endpoints []netipAddrPort
	if cmd.GetHasEndpoints() {
		endpoints, err = parseAddrPorts(cmd.GetEndpoints())
		if err != nil {
			return err
		}
		if endpoints == nil {
			endpoints = []netipAddrPort{}
		}
	}

	return r.applyHeartbeat(now, ttl, cmd.GetNodeId(), endpoints)
}

// commandTTL buyruqdagi TTL ni tekshiradi.
//
// Nol TTL nodeni darhol muddati o'tgan qilib qo'yardi — buni
// jimgina standart qiymatga aylantirish xatoni yashirardi, chunki
// jurnal allaqachon yozilgan bo'lardi.
func commandTTL(seconds uint64) (time.Duration, error) {
	if seconds == 0 {
		return 0, fmt.Errorf("%w: TTL berilmagan", ErrBadCommand)
	}
	return time.Duration(seconds) * time.Second, nil
}

func parsePrefixes(raw []string) ([]netipPrefix, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	out := make([]netipPrefix, 0, len(raw))
	for _, item := range raw {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("%w: prefiks (%s): %v", ErrBadCommand, item, err)
		}
		out = append(out, prefix)
	}
	return out, nil
}

func parseAddrPorts(raw []string) ([]netipAddrPort, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	out := make([]netipAddrPort, 0, len(raw))
	for _, item := range raw {
		addr, err := netip.ParseAddrPort(item)
		if err != nil {
			return nil, fmt.Errorf("%w: endpoint (%s): %v", ErrBadCommand, item, err)
		}
		out = append(out, addr)
	}
	return out, nil
}
