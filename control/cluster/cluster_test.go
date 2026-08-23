package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/freco-dev/cc01/control/ipam"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// freePort yadro bergan bo'sh portni qaytaradi.
//
// Sobit portlar ishlatilmaydi: testlar parallel ishlashi mumkin va
// band port butun to'plamni yiqitardi.
func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	defer listener.Close()

	return listener.Addr().(*net.TCPAddr).Port
}

// startCluster n ta nodedan iborat klaster ko'taradi va lider
// tanlanishini kutadi.
func startCluster(t *testing.T, n int) []*Node {
	t.Helper()

	addresses := make([]string, n)
	peers := make([]Peer, n)
	for i := range n {
		addresses[i] = fmt.Sprintf("127.0.0.1:%d", freePort(t))
		peers[i] = Peer{ID: fmt.Sprintf("n%d", i+1), Address: addresses[i]}
	}

	nodes := make([]*Node, n)
	for i := range n {
		dir, err := os.MkdirTemp("/tmp", "cc01raft")
		if err != nil {
			t.Fatalf("papka: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })

		node, err := Start(Config{
			ID:   peers[i].ID,
			Bind: addresses[i],
			Dir:  dir,
			// Faqat BITTA node bootstrap qiladi: ikkitasi qilsa
			// ikkita alohida klaster paydo bo'lardi.
			Bootstrap: i == 0,
			Peers:     peers,
			Logger:    quiet(),
		})
		if err != nil {
			t.Fatalf("node %d: %v", i, err)
		}

		nodes[i] = node
		t.Cleanup(func() { _ = node.Close() })
	}

	waitForLeader(t, nodes, 10*time.Second)
	return nodes
}

// waitForLeader klasterda aynan bitta lider paydo bo'lishini kutadi.
func waitForLeader(t *testing.T, nodes []*Node, timeout time.Duration) *Node {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var leaders []*Node
		for _, node := range nodes {
			if node.IsLeader() {
				leaders = append(leaders, node)
			}
		}

		if len(leaders) == 1 {
			return leaders[0]
		}
		if len(leaders) > 1 {
			t.Fatalf("%d ta lider — split brain", len(leaders))
		}

		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("%v ichida lider tanlanmadi", timeout)
	return nil
}

func allocCmd(id, prefix, owner string) *cc01v1.LeaseCommand {
	return &cc01v1.LeaseCommand{
		Now: timestamppb.New(time.Now()),
		Command: &cc01v1.LeaseCommand_Allocate{Allocate: &cc01v1.AllocateLease{
			LeaseId:    id,
			Prefix:     prefix,
			Owner:      owner,
			Tenant:     "t1",
			Parent:     "2a0e:1::/64",
			TtlSeconds: 3600,
		}},
	}
}

// leaseCount nodedagi ijaralar sonini qaytaradi.
func leaseCount(t *testing.T, node *Node) int {
	t.Helper()

	var count int
	if err := node.View(context.Background(), func(state *ipam.State) error {
		count = len(state.Leases)
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	return count
}

// Klaster ko'tarilib, bitta lider tanlashi kerak.
func TestCluster_ElectsSingleLeader(t *testing.T) {
	nodes := startCluster(t, 3)

	leader := waitForLeader(t, nodes, 5*time.Second)
	if leader == nil {
		t.Fatal("lider yo'q")
	}

	// Qolganlari liderning manzilini bilishi kerak. Bu xabar
	// tarqalishi biroz vaqt oladi, shuning uchun kutamiz.
	deadline := time.Now().Add(5 * time.Second)
	for {
		informed := 0
		for _, node := range nodes {
			if node.Leader() != "" {
				informed++
			}
		}
		if informed == len(nodes) {
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("%d/%d node liderni ko'rmayapti", len(nodes)-informed, len(nodes))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Liderga yozilgan buyruq HAMMA replikaga yetib borishi kerak.
func TestCluster_ReplicatesToAllNodes(t *testing.T) {
	nodes := startCluster(t, 3)
	leader := waitForLeader(t, nodes, 5*time.Second)

	lease, _, err := leader.Propose(context.Background(), allocCmd("l1", "2a0e:1::1/128", "node-a"))
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if lease.ID != "l1" {
		t.Fatalf("ijara ID'si %q", lease.ID)
	}

	// Replikatsiya asinxron — kutamiz.
	deadline := time.Now().Add(5 * time.Second)
	for {
		replicated := 0
		for _, node := range nodes {
			if leaseCount(t, node) == 1 {
				replicated++
			}
		}
		if replicated == len(nodes) {
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("faqat %d/%d nodega yetib bordi", replicated, len(nodes))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Lider bo'lmagan node yozuvni rad etishi va liderni ko'rsatishi
// kerak — busiz chaqiruvchi qayerga murojaat qilishni bilmasdi.
func TestCluster_FollowerRejectsWriteWithLeaderHint(t *testing.T) {
	nodes := startCluster(t, 3)
	leader := waitForLeader(t, nodes, 5*time.Second)

	var follower *Node
	for _, node := range nodes {
		if node != leader {
			follower = node
			break
		}
	}

	_, _, err := follower.Propose(context.Background(), allocCmd("l1", "2a0e:1::1/128", "node-a"))

	var notLeader *ErrNotLeader
	if !errors.As(err, &notLeader) {
		t.Fatalf("ErrNotLeader kutilgan edi, olindi: %v", err)
	}
	if notLeader.Leader == "" {
		t.Error("xato liderning manzilini ko'rsatmadi")
	}
}

// DoD (DEV_SPEC §8): lider yo'qolganda yangisi 5 soniyadan tez
// tanlanishi kerak.
func TestCluster_LeaderFailoverUnderFiveSeconds(t *testing.T) {
	nodes := startCluster(t, 3)
	leader := waitForLeader(t, nodes, 5*time.Second)

	// Liderga bir nechta yozuv — failover'dan keyin ular saqlanib
	// qolishi kerak.
	for i := range 3 {
		_, _, err := leader.Propose(context.Background(),
			allocCmd(fmt.Sprintf("l%d", i), fmt.Sprintf("2a0e:1::%d/128", i+1), "node-a"))
		if err != nil {
			t.Fatalf("Propose %d: %v", i, err)
		}
	}

	survivors := make([]*Node, 0, len(nodes)-1)
	for _, node := range nodes {
		if node != leader {
			survivors = append(survivors, node)
		}
	}

	start := time.Now()
	if err := leader.Close(); err != nil {
		t.Logf("liderni to'xtatish: %v", err)
	}

	next := waitForLeader(t, survivors, 5*time.Second)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Errorf("failover %v davom etdi, 5 s dan tez kutilgan edi", elapsed)
	}
	t.Logf("yangi lider %v ichida tanlandi", elapsed.Round(time.Millisecond))

	// Yangi lider tasdiqlangan yozuvlarni JURNALIDA saqlaydi, lekin
	// ularni FSM ga qo'llash biroz vaqt oladi — kutamiz.
	if err := next.Barrier(context.Background()); err != nil {
		t.Fatalf("Barrier: %v", err)
	}

	// Yozuvlar yo'qolmagan bo'lishi kerak.
	if got := leaseCount(t, next); got != 3 {
		t.Errorf("failover'dan keyin %d ta ijara qoldi, 3 kutilgan edi", got)
	}

	// Yangi lider yozishni davom ettira olishi kerak.
	if _, _, err := next.Propose(context.Background(),
		allocCmd("after", "2a0e:1::9/128", "node-b")); err != nil {
		t.Fatalf("yangi lider yoza olmadi: %v", err)
	}
}

// Kvorum yo'qolganda yozuv QABUL QILINMASLIGI kerak. Aks holda
// klaster bo'linganda ikkala tomon ham yozib, holat ajralib ketardi.
func TestCluster_RejectsWritesWithoutQuorum(t *testing.T) {
	nodes := startCluster(t, 3)
	leader := waitForLeader(t, nodes, 5*time.Second)

	// Uchtadan ikkitasini to'xtatamiz — kvorum qolmaydi.
	stopped := 0
	for _, node := range nodes {
		if node == leader {
			continue
		}
		_ = node.Close()
		stopped++
		if stopped == 2 {
			break
		}
	}

	// Eski lider bir muddat o'zini lider deb hisoblaydi (leader
	// lease), keyin voz kechadi.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, _, err := leader.Propose(context.Background(), allocCmd("x", "2a0e:1::5/128", "node-x"))
		if err != nil {
			return // yozuv rad etildi — kutilgan natija
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatal("kvorumsiz yozuv qabul qilindi")
}
