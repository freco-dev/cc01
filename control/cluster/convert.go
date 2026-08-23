package cluster

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/freco-dev/cc01/control/ipam"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// leaseToProto ijarani snapshot yozuviga aylantiradi.
func leaseToProto(lease *ipam.Lease) *cc01v1.LeaseRecord {
	record := &cc01v1.LeaseRecord{
		Id:        lease.ID,
		Prefix:    lease.Prefix.String(),
		Kind:      uint32(lease.Kind),
		State:     uint32(lease.State),
		Owner:     lease.Owner,
		Tenant:    lease.Tenant,
		Parent:    lease.Parent.String(),
		IssuedAt:  timestamppb.New(lease.IssuedAt),
		ExpiresAt: timestamppb.New(lease.ExpiresAt),
	}

	// Nol vaqtni yozmaymiz: u "karantinda emas" degani va uni
	// timestamp sifatida yozib qo'yish tiklashda 1-yil sanasiga
	// aylanardi.
	if !lease.ReleasedAt.IsZero() {
		record.ReleasedAt = timestamppb.New(lease.ReleasedAt)
	}

	return record
}

// leaseFromProto snapshot yozuvini ijaraga aylantiradi.
func leaseFromProto(record *cc01v1.LeaseRecord) (*ipam.Lease, error) {
	prefix, err := netip.ParsePrefix(record.GetPrefix())
	if err != nil {
		return nil, fmt.Errorf("cluster: snapshot prefiksi (%s): %w", record.GetPrefix(), err)
	}

	parent, err := netip.ParsePrefix(record.GetParent())
	if err != nil {
		return nil, fmt.Errorf("cluster: snapshot ota-prefiksi (%s): %w", record.GetParent(), err)
	}

	var released time.Time
	if record.GetReleasedAt() != nil {
		released = record.GetReleasedAt().AsTime()
	}

	return &ipam.Lease{
		ID:         record.GetId(),
		Prefix:     prefix,
		Kind:       ipam.LeaseKind(record.GetKind()),
		State:      ipam.LeaseState(record.GetState()),
		Owner:      record.GetOwner(),
		Tenant:     record.GetTenant(),
		Parent:     parent,
		IssuedAt:   record.GetIssuedAt().AsTime(),
		ExpiresAt:  record.GetExpiresAt().AsTime(),
		ReleasedAt: released,
	}, nil
}
