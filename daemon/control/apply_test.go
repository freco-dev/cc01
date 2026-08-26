package control

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/router"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

func testClient(t *testing.T) (*Client, *router.Router, *noise.Identity) {
	t.Helper()

	identity, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	r := router.New()
	client := &Client{
		cfg: Config{Identity: identity, Router: r},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return client, r, identity
}

func protoNode(t *testing.T, hostname, address, endpoint string) (*cc01v1.Node, noise.PublicKey) {
	t.Helper()

	identity, err := noise.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	key := identity.PublicKey()

	node := &cc01v1.Node{
		NodeId:    nodeIDFor(key),
		PublicKey: key[:],
		Hostname:  hostname,
		Addresses: []string{address},
	}
	if endpoint != "" {
		node.Endpoints = []string{endpoint}
	}
	return node, key
}

func TestApply_FullMapAddsPeers(t *testing.T) {
	client, r, _ := testClient(t)

	bob, bobKey := protoNode(t, "bob", "fd00:cc01::2/128", "10.0.0.2:51820")
	carol, carolKey := protoNode(t, "carol", "fd00:cc01::3/128", "10.0.0.3:51820")

	client.apply(&cc01v1.WatchNetworkMapResponse{
		Full:  true,
		Peers: []*cc01v1.Node{bob, carol},
	})

	if len(r.Peers()) != 2 {
		t.Fatalf("2 peer kutilgan, %d olindi", len(r.Peers()))
	}

	peer, ok := r.Peer(bobKey)
	if !ok {
		t.Fatal("bob qo'shilmadi")
	}
	if endpoint, has := peer.Endpoint(); !has || endpoint.String() != "10.0.0.2:51820" {
		t.Errorf("bob endpointi: %v", endpoint)
	}
	if _, ok := r.Peer(carolKey); !ok {
		t.Error("carol qo'shilmadi")
	}
}

// To'liq map mapda YO'Q peerlarni olib tashlashi kerak — bu delta
// yo'qolgan holatlarda holatni to'g'rilaydi.
func TestApply_FullMapRemovesStalePeers(t *testing.T) {
	client, r, _ := testClient(t)

	bob, bobKey := protoNode(t, "bob", "fd00:cc01::2/128", "")
	carol, carolKey := protoNode(t, "carol", "fd00:cc01::3/128", "")

	client.apply(&cc01v1.WatchNetworkMapResponse{
		Full: true, Peers: []*cc01v1.Node{bob, carol},
	})

	// Endi carol yo'q.
	client.apply(&cc01v1.WatchNetworkMapResponse{
		Full: true, Peers: []*cc01v1.Node{bob},
	})

	if _, ok := r.Peer(bobKey); !ok {
		t.Error("bob olib tashlanib ketdi")
	}
	if _, ok := r.Peer(carolKey); ok {
		t.Error("carol olib tashlanmadi")
	}
}

// Delta mavjud peerlarga tegmasligi kerak.
func TestApply_DeltaOnlyTouchesListedPeers(t *testing.T) {
	client, r, _ := testClient(t)

	bob, bobKey := protoNode(t, "bob", "fd00:cc01::2/128", "")
	client.apply(&cc01v1.WatchNetworkMapResponse{Full: true, Peers: []*cc01v1.Node{bob}})

	carol, carolKey := protoNode(t, "carol", "fd00:cc01::3/128", "")
	client.apply(&cc01v1.WatchNetworkMapResponse{Full: false, Peers: []*cc01v1.Node{carol}})

	if _, ok := r.Peer(bobKey); !ok {
		t.Error("delta bob'ni olib tashladi")
	}
	if _, ok := r.Peer(carolKey); !ok {
		t.Error("carol qo'shilmadi")
	}
}

func TestApply_DeltaRemovesByNodeID(t *testing.T) {
	client, r, _ := testClient(t)

	bob, bobKey := protoNode(t, "bob", "fd00:cc01::2/128", "")
	client.apply(&cc01v1.WatchNetworkMapResponse{Full: true, Peers: []*cc01v1.Node{bob}})

	client.apply(&cc01v1.WatchNetworkMapResponse{
		Full:    false,
		Removed: []string{bob.GetNodeId()},
	})

	if _, ok := r.Peer(bobKey); ok {
		t.Error("peer olib tashlanmadi")
	}
}

// Node o'zini peer sifatida qo'shmasligi kerak — u o'zi bilan sessiya
// qurmaydi.
func TestApply_IgnoresSelf(t *testing.T) {
	client, r, identity := testClient(t)

	self := identity.PublicKey()
	client.apply(&cc01v1.WatchNetworkMapResponse{
		Full: true,
		Peers: []*cc01v1.Node{{
			NodeId:    nodeIDFor(self),
			PublicKey: self[:],
			Hostname:  "men",
			Addresses: []string{"fd00:cc01::1/128"},
		}},
	})

	if len(r.Peers()) != 0 {
		t.Errorf("o'zi peer sifatida qo'shildi: %d", len(r.Peers()))
	}
}

// Manzilsiz peer bilan hech narsa qilib bo'lmaydi: uning allowed_ips i
// bo'sh bo'lsa na marshrutlash, na cryptokey routing ishlaydi.
func TestApply_SkipsPeerWithoutAddresses(t *testing.T) {
	client, r, _ := testClient(t)

	bob, _ := protoNode(t, "bob", "fd00:cc01::2/128", "")
	bob.Addresses = nil

	client.apply(&cc01v1.WatchNetworkMapResponse{Full: true, Peers: []*cc01v1.Node{bob}})

	if len(r.Peers()) != 0 {
		t.Errorf("manzilsiz peer qo'shildi: %d", len(r.Peers()))
	}
}

func TestApply_SkipsInvalidPublicKey(t *testing.T) {
	client, r, _ := testClient(t)

	client.apply(&cc01v1.WatchNetworkMapResponse{
		Full: true,
		Peers: []*cc01v1.Node{{
			NodeId:    "qisqa",
			PublicKey: []byte{1, 2, 3},
			Addresses: []string{"fd00:cc01::2/128"},
		}},
	})

	if len(r.Peers()) != 0 {
		t.Errorf("yaroqsiz kalitli peer qo'shildi: %d", len(r.Peers()))
	}
}

// allowed_ips o'zgarsa peer qayta yaratilishi kerak, aks holda
// marshrutlash jadvali eski qolardi.
func TestApply_UpdatesChangedAllowedIPs(t *testing.T) {
	client, r, _ := testClient(t)

	bob, bobKey := protoNode(t, "bob", "fd00:cc01::2/128", "")
	client.apply(&cc01v1.WatchNetworkMapResponse{Full: true, Peers: []*cc01v1.Node{bob}})

	// Bob subnet-router bo'ldi.
	bob.Addresses = []string{"fd00:cc01::2/128", "fd00:cc01:5555::/64"}
	client.apply(&cc01v1.WatchNetworkMapResponse{Full: false, Peers: []*cc01v1.Node{bob}})

	peer, ok := r.Peer(bobKey)
	if !ok {
		t.Fatal("bob yo'qoldi")
	}
	if len(peer.AllowedIPs()) != 2 {
		t.Errorf("2 prefiks kutilgan, %d olindi: %v", len(peer.AllowedIPs()), peer.AllowedIPs())
	}
}

// Endpoint o'zgarishi peerni qayta yaratmasligi kerak — sessiya
// saqlanib qolishi kerak.
func TestApply_EndpointUpdateKeepsPeer(t *testing.T) {
	client, r, _ := testClient(t)

	bob, bobKey := protoNode(t, "bob", "fd00:cc01::2/128", "10.0.0.2:51820")
	client.apply(&cc01v1.WatchNetworkMapResponse{Full: true, Peers: []*cc01v1.Node{bob}})

	before, _ := r.Peer(bobKey)

	bob.Endpoints = []string{"10.0.0.99:51820"}
	client.apply(&cc01v1.WatchNetworkMapResponse{Full: false, Peers: []*cc01v1.Node{bob}})

	after, ok := r.Peer(bobKey)
	if !ok {
		t.Fatal("bob yo'qoldi")
	}
	if before != after {
		t.Error("endpoint o'zgarishi peerni qayta yaratdi")
	}

	endpoint, _ := after.Endpoint()
	if endpoint.String() != "10.0.0.99:51820" {
		t.Errorf("endpoint yangilanmadi: %v", endpoint)
	}
}

func TestParsePrefixes_SkipsInvalidAndIPv4(t *testing.T) {
	got := parsePrefixes([]string{
		"fd00:cc01::1/128",
		"10.0.0.0/8", // IPv4 — overlay faqat IPv6
		"axlat",      // parse bo'lmaydi
		"fd00:cc01:1::/64",
	})

	want := []netip.Prefix{
		netip.MustParsePrefix("fd00:cc01::1/128"),
		netip.MustParsePrefix("fd00:cc01:1::/64"),
	}

	if len(got) != len(want) {
		t.Fatalf("%d prefiks kutilgan, %d olindi: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %v kutilgan, %v olindi", i, want[i], got[i])
		}
	}
}

// node_id formulasi CP dagi bilan bir xil bo'lishi SHART, aks holda
// o'chirish xabarlari hech qachon mos kelmaydi.
func TestNodeIDFor_MatchesSpec(t *testing.T) {
	identity, _ := noise.GenerateIdentity()
	key := identity.PublicKey()

	id := nodeIDFor(key)
	if len(id) != 64 {
		t.Errorf("SHA-256 hex 64 belgi bo'lishi kerak, %d olindi", len(id))
	}
	if id != nodeIDFor(key) {
		t.Error("formula barqaror emas")
	}
}
