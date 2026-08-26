package cluster

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/freco-dev/cc01/control/registry"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// Node ro'yxati Raft jurnalidan o'tishi kerak. Aks holda u faqat
// liderning xotirasida qolib, failover'da yo'qolardi.

var base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func registerCmd(now time.Time, seed, tenant string, ttl time.Duration) *cc01v1.LeaseCommand {
	key := make([]byte, 32)
	copy(key, seed)

	return &cc01v1.LeaseCommand{
		Now: timestamppb.New(now),
		Command: &cc01v1.LeaseCommand_RegisterNode{
			RegisterNode: &cc01v1.RegisterNode{
				PublicKey:  key,
				Tenant:     tenant,
				Hostname:   seed,
				Addresses:  []string{"2a0e:1::1/128"},
				Endpoints:  []string{"203.0.113.1:51820"},
				TtlSeconds: uint64(ttl / time.Second),
			},
		},
	}
}

func expireCmd(now time.Time) *cc01v1.LeaseCommand {
	return &cc01v1.LeaseCommand{
		Now:     timestamppb.New(now),
		Command: &cc01v1.LeaseCommand_ExpireNodes{ExpireNodes: &cc01v1.ExpireNodes{}},
	}
}

// Jurnaldan o'tgan ro'yxat FSM ning registry'sida ko'rinishi kerak.
func TestFSM_AppliesRegistryCommands(t *testing.T) {
	fsm := NewFSM(registry.New(registry.Options{}), quiet())

	result := applyTo(t, fsm, registerCmd(base, "laptop", "t1", time.Minute))
	if result.err != nil {
		t.Fatalf("Apply: %v", result.err)
	}
	if result.node == nil {
		t.Fatal("node qaytmadi")
	}

	if _, ok := fsm.Nodes().Node(result.node.ID); !ok {
		t.Error("node registry'ga tushmadi")
	}
	if fsm.Nodes().Version() == 0 {
		t.Error("versiya oshmadi")
	}
}

// Ikkita replika AYNAN bir jurnalni ko'rib, bir xil holatga
// kelishi kerak.
//
// Eng nozik joyi — muddat tekshiruvi: u map bo'ylab yuradi va Go'da
// map tartibi tasodifiy. Saralanmasa, har bir replikada bir xil
// versiya BOSHQA nodega tegib qolardi.
//
// ⚠️ Buni yakuniy holatni solishtirib TOPIB BO'LMAYDI: hamma node
// chiqarilgach holat baribir bir xil, delta esa qaytarishdan oldin
// saralanadi. Ajralish faqat klientning `since` versiyasi partiya
// O'RTASIGA tushganda ko'rinadi — o'shanda replikalar boshqa-boshqa
// nodelarni "o'chirilgan" deb aytadi.
func TestFSM_RegistryIsDeterministic(t *testing.T) {
	const doomed = 8

	log := []*cc01v1.LeaseCommand{
		// Tirik qoladi: NetworkMap so'rash uchun kerak.
		registerCmd(base, "survivor", "t1", time.Hour),
	}
	for i := range doomed {
		log = append(log, registerCmd(base, string(rune('a'+i)), "t1", time.Minute))
	}

	type replica struct {
		fsm    *FSM
		before uint64
	}

	replicas := make([]replica, 3)
	for i := range replicas {
		fsm := NewFSM(registry.New(registry.Options{}), quiet())
		for _, cmd := range log {
			if result := applyTo(t, fsm, cmd); result.err != nil {
				t.Fatalf("replika %d: %v", i, result.err)
			}
		}

		// Muddat tekshiruvidan OLDINGI versiya.
		before := fsm.Nodes().Version()

		if result := applyTo(t, fsm, expireCmd(base.Add(2*time.Minute))); result.err != nil {
			t.Fatalf("replika %d muddat: %v", i, result.err)
		}
		replicas[i] = replica{fsm: fsm, before: before}
	}

	self := replicas[0].fsm.Nodes()
	var selfID string
	nodes, _ := self.Snapshot()
	for _, node := range nodes {
		if node.Hostname == "survivor" {
			selfID = node.ID
		}
	}
	if selfID == "" {
		t.Fatal("tirik node topilmadi")
	}

	// `since` ni partiya O'RTASIGA qo'yamiz.
	since := replicas[0].before + doomed/2

	var want []string
	for i, r := range replicas {
		if r.before != replicas[0].before {
			t.Fatalf("replika %d boshlang'ich versiyasi farq qildi: %d va %d",
				i, r.before, replicas[0].before)
		}

		netmap, err := r.fsm.Nodes().NetworkMapFor(selfID, since)
		if err != nil {
			t.Fatalf("replika %d: %v", i, err)
		}

		if i == 0 {
			want = netmap.Removed
			if len(want) == 0 {
				t.Fatal("delta bo'sh — test hech nimani solishtirmaydi")
			}
			continue
		}

		if len(netmap.Removed) != len(want) {
			t.Errorf("replika %d: %d ta o'chirilgan, %d kutilgan edi",
				i, len(netmap.Removed), len(want))
			continue
		}
		for j := range want {
			if netmap.Removed[j] != want[j] {
				t.Errorf("replika %d delta'si ajraldi:\n  %v\n  %v",
					i, netmap.Removed, want)
				break
			}
		}
	}
}

// Snapshot nodelarni ham, versiyani ham olib o'tishi kerak.
func TestFSM_SnapshotCarriesNodes(t *testing.T) {
	fsm := NewFSM(registry.New(registry.Options{}), quiet())

	for _, name := range []string{"laptop", "server", "phone"} {
		if result := applyTo(t, fsm, registerCmd(base, name, "t1", time.Hour)); result.err != nil {
			t.Fatalf("Apply: %v", result.err)
		}
	}

	wantNodes, wantVersion := fsm.Nodes().Snapshot()

	var buffer bytes.Buffer
	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := snap.Persist(&fakeSink{Writer: &buffer}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	restoredFSM := NewFSM(registry.New(registry.Options{}), quiet())
	if err := restoredFSM.Restore(io.NopCloser(&buffer)); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	gotNodes, gotVersion := restoredFSM.Nodes().Snapshot()

	if gotVersion != wantVersion {
		t.Errorf("versiya %d, %d kutilgan edi — delta sinxronizatsiyasi buzilardi",
			gotVersion, wantVersion)
	}
	if len(gotNodes) != len(wantNodes) {
		t.Fatalf("%d node tiklandi, %d kutilgan edi", len(gotNodes), len(wantNodes))
	}

	for i := range wantNodes {
		if gotNodes[i].ID != wantNodes[i].ID {
			t.Errorf("node %d: %s, %s kutilgan edi", i, gotNodes[i].ID, wantNodes[i].ID)
		}
		if !gotNodes[i].ExpiresAt.Equal(wantNodes[i].ExpiresAt) {
			t.Errorf("node %d muddati: %v, %v kutilgan edi",
				i, gotNodes[i].ExpiresAt, wantNodes[i].ExpiresAt)
		}
		if len(gotNodes[i].Addresses) != len(wantNodes[i].Addresses) {
			t.Errorf("node %d manzillari yo'qoldi", i)
		}
	}
}

// TTL buyruqdan olinishi kerak, konstantadan emas: konstanta
// o'zgarsa eski jurnal boshqacha qo'llanib, replikalar ajralardi.
func TestFSM_RegistryTTLComesFromCommand(t *testing.T) {
	fsm := NewFSM(registry.New(registry.Options{}), quiet())

	result := applyTo(t, fsm, registerCmd(base, "laptop", "t1", 90*time.Second))
	if result.err != nil {
		t.Fatalf("Apply: %v", result.err)
	}

	want := base.Add(90 * time.Second)
	if !result.node.ExpiresAt.Equal(want) {
		t.Errorf("muddat %v, %v kutilgan edi", result.node.ExpiresAt, want)
	}
}

// TTL siz buyruq QABUL QILINMASLIGI kerak: uni jimgina standart
// qiymatga aylantirish xatoni yashirardi, chunki jurnal allaqachon
// yozilgan bo'lardi.
func TestFSM_RegistryRejectsZeroTTL(t *testing.T) {
	fsm := NewFSM(registry.New(registry.Options{}), quiet())

	result := applyTo(t, fsm, registerCmd(base, "laptop", "t1", 0))
	if result.err == nil {
		t.Fatal("TTL siz buyruq qabul qilindi")
	}
}

// fakeSink — Persist uchun oddiy yozuvchi.
type fakeSink struct {
	io.Writer
	cancelled bool
}

func (s *fakeSink) Close() error  { return nil }
func (s *fakeSink) ID() string    { return "test" }
func (s *fakeSink) Cancel() error { s.cancelled = true; return nil }

var (
	_ raft.SnapshotSink = (*fakeSink)(nil)
	_                   = proto.Marshal
)
