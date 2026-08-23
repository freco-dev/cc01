package control

import (
	"net/netip"
	"slices"

	"github.com/freco-dev/cc01/daemon/noise"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// apply NetworkMap ni routerdagi peerlarga aylantiradi.
//
// Bu — CP va datapath o'rtasidagi yagona ko'prik. CP "kim bor va u
// qayerda" deb aytadi, router esa "qaysi paket qayerga ketadi" ni hal
// qiladi.
func (c *Client) apply(netmap *cc01v1.WatchNetworkMapResponse) {
	if netmap.GetFull() {
		c.reconcile(netmap.GetPeers())
	} else {
		for _, peer := range netmap.GetPeers() {
			c.upsertPeer(peer)
		}
	}

	for _, nodeID := range netmap.GetRemoved() {
		c.removeByNodeID(nodeID)
	}

	c.applyRelays(netmap.GetRelays())

	c.log.Debug("NetworkMap qo'llandi",
		"version", netmap.GetVersion(), "full", netmap.GetFull(),
		"peers", len(netmap.GetPeers()), "removed", len(netmap.GetRemoved()))

	if c.cfg.OnNetworkMap != nil {
		c.cfg.OnNetworkMap()
	}
}

// reconcile to'liq mapni qo'llaydi: mapda yo'q peerlar olib tashlanadi.
//
// Bu delta yo'qolgan holatlarda ham holatni to'g'rilaydi — shuning
// uchun qayta ulanganda har doim to'liq map so'raladi.
func (c *Client) reconcile(peers []*cc01v1.Node) {
	wanted := make(map[noise.PublicKey]struct{}, len(peers))

	for _, peer := range peers {
		key, ok := publicKey(peer.GetPublicKey())
		if !ok {
			continue
		}
		wanted[key] = struct{}{}
		c.upsertPeer(peer)
	}

	// Mapda yo'q peerlarni olib tashlaymiz. O'zimizni ham tekshiramiz:
	// CP `self` ni peerlar ro'yxatiga qo'shmaydi.
	self := c.cfg.Identity.PublicKey()
	for _, existing := range c.cfg.Router.Peers() {
		if existing.PublicKey == self {
			continue
		}
		if _, keep := wanted[existing.PublicKey]; !keep {
			c.log.Info("peer olib tashlandi", "peer", existing.PublicKey)
			c.cfg.Router.RemovePeer(existing.PublicKey)
		}
	}
}

// upsertPeer bitta peerni qo'shadi yoki yangilaydi.
func (c *Client) upsertPeer(node *cc01v1.Node) {
	key, ok := publicKey(node.GetPublicKey())
	if !ok {
		c.log.Warn("peer public kaliti yaroqsiz", "node", shortID(node.GetNodeId()))
		return
	}

	// O'zimizni peer sifatida qo'shmaymiz.
	if key == c.cfg.Identity.PublicKey() {
		return
	}

	allowed := parsePrefixes(node.GetAddresses())
	if len(allowed) == 0 {
		// Manzilsiz peer bilan hech narsa qila olmaymiz: uning
		// allowed_ips i bo'sh bo'lsa na marshrutlash, na cryptokey
		// routing ishlaydi.
		c.log.Debug("peer manzilsiz, o'tkazib yuborildi", "node", shortID(node.GetNodeId()))
		return
	}

	endpoint := firstEndpoint(node.GetEndpoints())

	existing, known := c.cfg.Router.Peer(key)
	if known {
		// allowed_ips o'zgargan bo'lishi mumkin — peerni qayta
		// yaratamiz, shunda marshrutlash jadvali ham yangilanadi.
		if !samePrefixes(existing.AllowedIPs(), allowed) {
			c.cfg.Router.RemovePeer(key)
			known = false
		} else if endpoint.IsValid() {
			existing.SetEndpoint(endpoint)
			return
		} else {
			return
		}
	}

	peer, err := c.cfg.Router.AddPeer(key, allowed)
	if err != nil {
		c.log.Warn("peer qo'shilmadi", "node", shortID(node.GetNodeId()), "err", err)
		return
	}
	if endpoint.IsValid() {
		peer.SetEndpoint(endpoint)
	}

	c.log.Info("peer qo'shildi",
		"node", shortID(node.GetNodeId()), "hostname", node.GetHostname(),
		"addresses", node.GetAddresses(), "endpoint", endpoint)
}

// removeByNodeID node_id bo'yicha peerni olib tashlaydi.
//
// Router peerlarni public kalit bo'yicha saqlaydi, CP esa node_id
// yuboradi. node_id = SHA-256(pubkey) bo'lgani uchun teskari
// hisoblab bo'lmaydi — mavjud peerlar bo'yicha qidiramiz.
func (c *Client) removeByNodeID(nodeID string) {
	for _, peer := range c.cfg.Router.Peers() {
		if nodeIDFor(peer.PublicKey) != nodeID {
			continue
		}
		c.log.Info("peer olib tashlandi", "node", shortID(nodeID))
		c.cfg.Router.RemovePeer(peer.PublicKey)
		return
	}
}

func publicKey(raw []byte) (noise.PublicKey, bool) {
	var key noise.PublicKey
	if len(raw) != len(key) {
		return key, false
	}
	copy(key[:], raw)
	return key, !key.IsZero()
}

func parsePrefixes(raw []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, item := range raw {
		prefix, err := netip.ParsePrefix(item)
		if err != nil || !prefix.Addr().Is6() {
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes
}

func firstEndpoint(raw []string) netip.AddrPort {
	for _, item := range raw {
		if endpoint, err := netip.ParseAddrPort(item); err == nil {
			return endpoint
		}
	}
	return netip.AddrPort{}
}

func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}

	seen := make(map[netip.Prefix]int, len(a))
	for _, prefix := range a {
		seen[prefix]++
	}
	for _, prefix := range b {
		seen[prefix]--
		if seen[prefix] < 0 {
			return false
		}
	}
	return true
}

// applyRelays CP e'lon qilgan relay ro'yxatini yuqoriga uzatadi.
//
// Ro'yxat ustuvorlik bo'yicha tartiblanadi: kichikroq `priority`
// oldinroq turadi (ARCHITECTURE.md §6.4 dagi tanlash algoritmining
// soddalashtirilgan ko'rinishi).
func (c *Client) applyRelays(relays []*cc01v1.Relay) {
	if c.cfg.OnRelays == nil || len(relays) == 0 {
		return
	}

	parsed := make([]RelayInfo, 0, len(relays))
	for _, item := range relays {
		key, ok := publicKey(item.GetPublicKey())
		if !ok {
			continue
		}

		endpoint, err := netip.ParseAddrPort(item.GetEndpoint())
		if err != nil {
			c.log.Warn("relay manzili yaroqsiz",
				"relay", item.GetId(), "endpoint", item.GetEndpoint())
			continue
		}

		parsed = append(parsed, RelayInfo{
			ID:        item.GetId(),
			PublicKey: key,
			Endpoint:  endpoint,
			Region:    item.GetRegion(),
			Priority:  item.GetPriority(),
		})
	}

	if len(parsed) == 0 {
		return
	}

	slices.SortFunc(parsed, func(a, b RelayInfo) int {
		return int(a.Priority) - int(b.Priority)
	})

	c.cfg.OnRelays(parsed)
}
