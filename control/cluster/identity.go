package cluster

import (
	"context"
	"errors"
	"fmt"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/protobuf/proto"
)

// ErrIdentityMismatch — node boshqa sertifikat bilan keldi.
//
// Bu jiddiy hodisa: yo node kalitini yo'qotgan (va uni qo'lda
// tiklash kerak), yo kimdir uning o'rniga o'tmoqchi.
var ErrIdentityMismatch = errors.New("cluster: node sertifikati bog'langanidan farq qiladi")

// IdentityStore — nodelarni sertifikatlariga bog'laydi.
//
// Interfeys sifatida ajratilgan: klastersiz rejimda xotiradagi
// implementatsiya ishlatiladi va CP kodi ikkalasi orasida farq
// ko'rmasligi kerak.
type IdentityStore interface {
	// Bind nodeni sertifikatga bog'laydi.
	//
	// Allaqachon BOSHQA sertifikatga bog'langan bo'lsa
	// ErrIdentityMismatch qaytadi — bog'lanish jimgina
	// almashtirilmaydi.
	Bind(ctx context.Context, nodeID, certPin string) error

	// Identity — nodening bog'langan sertifikati.
	Identity(ctx context.Context, nodeID string) (string, bool, error)
}

// Bind nodeni sertifikatga bog'laydi (Raft orqali).
func (n *Node) Bind(ctx context.Context, nodeID, certPin string) error {
	if nodeID == "" || certPin == "" {
		return errors.New("cluster: node_id va sertifikat pini kerak")
	}

	// Allaqachon o'sha sertifikatga bog'langan bo'lsa jurnalga
	// yozmaymiz: har bir ro'yxatdan o'tish yangi yozuv qo'shsa,
	// jurnal keraksiz o'sardi.
	existing, found, err := n.Identity(ctx, nodeID)
	if err != nil {
		return err
	}
	if found {
		if existing == certPin {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrIdentityMismatch, nodeID)
	}

	cmd := &cc01v1.LeaseCommand{
		Command: &cc01v1.LeaseCommand_Bind{Bind: &cc01v1.BindNodeIdentity{
			NodeId:  nodeID,
			CertPin: certPin,
		}},
	}

	if !n.IsLeader() {
		return &ErrNotLeader{Leader: n.Leader()}
	}

	encoded, err := proto.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("cluster: buyruqni kodlash: %w", err)
	}

	future := n.raft.Apply(encoded, applyTimeout)
	if err := future.Error(); err != nil {
		return fmt.Errorf("cluster: bog'lanishni yozish: %w", err)
	}

	result, ok := future.Response().(applyResult)
	if !ok {
		return errors.New("cluster: kutilmagan javob turi")
	}
	return result.err
}

// Identity nodening bog'langan sertifikatini qaytaradi.
func (n *Node) Identity(ctx context.Context, nodeID string) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}

	pin, found := n.fsm.identity(nodeID)
	return pin, found, nil
}

var _ IdentityStore = (*Node)(nil)
