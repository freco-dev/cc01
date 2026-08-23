package ipam

import (
	"errors"
	"fmt"
	"testing"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func testTime() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) }

func allocCmd(id, prefix, owner string, now time.Time) *cc01v1.LeaseCommand {
	return &cc01v1.LeaseCommand{
		Now: timestamppb.New(now),
		Command: &cc01v1.LeaseCommand_Allocate{Allocate: &cc01v1.AllocateLease{
			LeaseId:    id,
			Prefix:     prefix,
			Kind:       uint32(KindNode),
			Owner:      owner,
			Tenant:     "t1",
			Parent:     "2a0e:1::/64",
			TtlSeconds: uint64(LeaseTTL / time.Second),
		}},
	}
}

// Raft ning asosiy sharti: bir xil jurnal bir xil holatga olib
// kelishi kerak. Aks holda replikalar jimgina ajralib ketadi va buni
// faqat mijoz noto'g'ri javob olganda sezish mumkin.
func TestApply_IsDeterministic(t *testing.T) {
	now := testTime()

	log := []*cc01v1.LeaseCommand{
		allocCmd("l1", "2a0e:1::1/128", "node-a", now),
		allocCmd("l2", "2a0e:1::2/128", "node-b", now),
		{
			Now: timestamppb.New(now.Add(time.Minute)),
			Command: &cc01v1.LeaseCommand_Renew{Renew: &cc01v1.RenewLease{
				LeaseId: "l1", TtlSeconds: uint64(LeaseTTL / time.Second),
			}},
		},
		allocCmd("l3", "2a0e:1::3/128", "node-c", now),
		{
			Now: timestamppb.New(now.Add(2 * time.Minute)),
			Command: &cc01v1.LeaseCommand_Release{Release: &cc01v1.ReleaseLease{
				LeaseId: "l2",
			}},
		},
		{
			Now:     timestamppb.New(now.Add(3 * time.Hour)),
			Command: &cc01v1.LeaseCommand_Sweep{Sweep: &cc01v1.SweepLeases{}},
		},
	}

	// Ikkita mustaqil "replika" bir xil jurnalni qo'llaydi.
	first, second := NewState(), NewState()
	for _, cmd := range log {
		// Har bir replika o'z nusxasini oladi — Raft ham baytlarni
		// qayta dekodlaydi.
		_, _, errA := first.Apply(proto.Clone(cmd).(*cc01v1.LeaseCommand))
		_, _, errB := second.Apply(proto.Clone(cmd).(*cc01v1.LeaseCommand))

		if (errA == nil) != (errB == nil) {
			t.Fatalf("replikalar turlicha javob berdi: %v va %v", errA, errB)
		}
	}

	assertSameState(t, first, second)
}

// Bir xil buyruq ikki marta qo'llansa yangi ijara yaratilmasligi
// kerak: Raft buyruqni takroriy yetkazishi mumkin.
func TestApply_AllocateIsIdempotent(t *testing.T) {
	state := NewState()
	cmd := allocCmd("l1", "2a0e:1::1/128", "node-a", testTime())

	first, _, err := state.Apply(cmd)
	if err != nil {
		t.Fatalf("birinchi: %v", err)
	}

	second, _, err := state.Apply(cmd)
	if err != nil {
		t.Fatalf("takroriy: %v", err)
	}

	if len(state.Leases) != 1 {
		t.Fatalf("%d ta ijara yaratildi, 1 kutilgan edi", len(state.Leases))
	}
	if first.ID != second.ID || first.Prefix != second.Prefix {
		t.Errorf("takroriy qo'llash boshqa natija berdi: %v / %v", first, second)
	}
}

// Band prefiksga buyruq kelsa aniq xato qaytishi kerak — taklif
// qiluvchi shuni ko'rib qayta urinadi.
func TestApply_RejectsTakenPrefix(t *testing.T) {
	state := NewState()

	if _, _, err := state.Apply(allocCmd("l1", "2a0e:1::1/128", "node-a", testTime())); err != nil {
		t.Fatalf("birinchi: %v", err)
	}

	_, _, err := state.Apply(allocCmd("l2", "2a0e:1::1/128", "node-b", testTime()))
	if !errors.Is(err, ErrPrefixTaken) {
		t.Fatalf("ErrPrefixTaken kutilgan edi, olindi: %v", err)
	}
}

// TTL buyruqda keladi, konstantadan o'qilmaydi: konstanta o'zgarsa
// eski jurnal boshqacha qo'llanib, replikalar ajralib ketardi.
func TestApply_UsesTTLFromCommand(t *testing.T) {
	state := NewState()
	now := testTime()

	cmd := allocCmd("l1", "2a0e:1::1/128", "node-a", now)
	cmd.GetAllocate().TtlSeconds = 90

	lease, _, err := state.Apply(cmd)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := lease.ExpiresAt.Sub(now); got != 90*time.Second {
		t.Errorf("muddat %v, 90s kutilgan edi", got)
	}
}

// Vaqt ham buyruqdan olinadi — Apply ichida soat o'qilmasligi kerak.
func TestApply_UsesTimeFromCommand(t *testing.T) {
	state := NewState()
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	lease, _, err := state.Apply(allocCmd("l1", "2a0e:1::1/128", "node-a", past))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !lease.IssuedAt.Equal(past) {
		t.Errorf("IssuedAt = %v, buyruqdagi %v kutilgan edi", lease.IssuedAt, past)
	}
}

func TestApply_RejectsMalformedCommand(t *testing.T) {
	state := NewState()

	cases := map[string]*cc01v1.LeaseCommand{
		"bo'sh":            nil,
		"turi yo'q":        {Now: timestamppb.New(testTime())},
		"prefiks yaroqsiz": allocCmd("l1", "bunday-emas", "node-a", testTime()),
		"ijara ID'si yo'q": allocCmd("", "2a0e:1::1/128", "node-a", testTime()),
	}

	for name, cmd := range cases {
		if _, _, err := state.Apply(cmd); err == nil {
			t.Errorf("%s: xato kutilgan edi", name)
		}
	}
}

// assertSameState ikkita holatning bir xilligini tekshiradi.
func assertSameState(t *testing.T, a, b *State) {
	t.Helper()

	if len(a.Leases) != len(b.Leases) {
		t.Fatalf("ijaralar soni: %d va %d", len(a.Leases), len(b.Leases))
	}

	for id, first := range a.Leases {
		second, ok := b.Leases[id]
		if !ok {
			t.Fatalf("%s faqat bitta replikada bor", id)
		}
		if summarize(first) != summarize(second) {
			t.Fatalf("%s farq qiladi:\n  %s\n  %s", id, summarize(first), summarize(second))
		}
	}

	if len(a.ByPrefix) != len(b.ByPrefix) {
		t.Errorf("ByPrefix indeksi: %d va %d", len(a.ByPrefix), len(b.ByPrefix))
	}
	for prefix, id := range a.ByPrefix {
		if b.ByPrefix[prefix] != id {
			t.Errorf("ByPrefix[%v]: %q va %q", prefix, id, b.ByPrefix[prefix])
		}
	}
}

func summarize(lease *Lease) string {
	return fmt.Sprintf("%s %v %d %s %s %s %s",
		lease.ID, lease.Prefix, lease.State, lease.Owner,
		lease.IssuedAt.UTC(), lease.ExpiresAt.UTC(), lease.ReleasedAt.UTC())
}
