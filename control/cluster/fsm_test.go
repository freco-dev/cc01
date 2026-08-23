package cluster

import (
	"bytes"
	"io"
	"net/netip"
	"testing"

	"github.com/freco-dev/cc01/control/ipam"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"github.com/hashicorp/raft"
	"google.golang.org/protobuf/proto"
)

// sinkStub — raft.SnapshotSink o'rniga.
type sinkStub struct {
	bytes.Buffer
	cancelled bool
	closed    bool
}

func (s *sinkStub) ID() string { return "test" }
func (s *sinkStub) Cancel() error {
	s.cancelled = true
	return nil
}
func (s *sinkStub) Close() error {
	s.closed = true
	return nil
}

func applyTo(t *testing.T, fsm *FSM, cmd *cc01v1.LeaseCommand) applyResult {
	t.Helper()

	encoded, err := proto.Marshal(cmd)
	if err != nil {
		t.Fatalf("kodlash: %v", err)
	}

	result, ok := fsm.Apply(&raft.Log{Data: encoded}).(applyResult)
	if !ok {
		t.Fatal("kutilmagan javob turi")
	}
	return result
}

func allocateCommand(id, prefix string) *cc01v1.LeaseCommand {
	return allocCmd(id, prefix, "node-a")
}

// Snapshot olingan holat qayta tiklanganda bir xil bo'lishi kerak —
// indekslari bilan birga.
func TestFSM_SnapshotRoundTrip(t *testing.T) {
	fsm := NewFSM(quiet())

	for i := range 5 {
		cmd := allocateCommand(string(rune('a'+i)), netip.PrefixFrom(addrAt(i+1), 128).String())
		if result := applyTo(t, fsm, cmd); result.err != nil {
			t.Fatalf("Apply %d: %v", i, result.err)
		}
	}

	snapshot, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	sink := &sinkStub{}
	if err := snapshot.Persist(sink); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if !sink.closed {
		t.Error("sink yopilmadi")
	}

	restored := NewFSM(quiet())
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	var before, after map[netip.Prefix]string
	_ = fsm.View(func(state *ipam.State) error {
		before = copyIndex(state.ByPrefix)
		return nil
	})
	_ = restored.View(func(state *ipam.State) error {
		after = copyIndex(state.ByPrefix)
		return nil
	})

	if len(before) != len(after) {
		t.Fatalf("prefiks indeksi: %d va %d", len(before), len(after))
	}
	for prefix, id := range before {
		if after[prefix] != id {
			t.Errorf("%v: %q va %q", prefix, id, after[prefix])
		}
	}
}

// Bo'sh holat ham to'g'ri tiklanishi kerak.
func TestFSM_SnapshotOfEmptyState(t *testing.T) {
	fsm := NewFSM(quiet())

	snapshot, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	sink := &sinkStub{}
	if err := snapshot.Persist(sink); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	restored := NewFSM(quiet())
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		t.Fatalf("Restore: %v", err)
	}
}

// Buzilgan snapshot tiklanmasligi va aniq xato berishi kerak.
func TestFSM_RejectsCorruptSnapshot(t *testing.T) {
	fsm := NewFSM(quiet())

	// Uzunlik maydoni ulkan son — usiz shuncha bayt ajratishga
	// urinardik.
	corrupt := []byte{0xff, 0xff, 0xff, 0xff, 0x01, 0x02}

	if err := fsm.Restore(io.NopCloser(bytes.NewReader(corrupt))); err == nil {
		t.Fatal("buzilgan snapshot qabul qilindi")
	}
}

// O'qib bo'lmaydigan jurnal yozuvi butun klasterni to'xtatmasligi
// kerak: o'sha yozuv hamma replikada bir xil, ya'ni panic butun
// klasterni o'ldirardi.
func TestFSM_SurvivesUnreadableEntry(t *testing.T) {
	fsm := NewFSM(quiet())

	result, ok := fsm.Apply(&raft.Log{Index: 7, Data: []byte{0xff, 0xff}}).(applyResult)
	if !ok {
		t.Fatal("kutilmagan javob turi")
	}
	if result.err == nil {
		t.Error("xato kutilgan edi")
	}

	// FSM ishlashda davom etishi kerak.
	if r := applyTo(t, fsm, allocateCommand("l1", "2a0e:1::1/128")); r.err != nil {
		t.Fatalf("keyingi buyruq qo'llanmadi: %v", r.err)
	}
}

func addrAt(i int) netip.Addr {
	addr := netip.MustParseAddr("2a0e:1::")
	for range i {
		addr = addr.Next()
	}
	return addr
}

func copyIndex(src map[netip.Prefix]string) map[netip.Prefix]string {
	out := make(map[netip.Prefix]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
