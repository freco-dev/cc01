package router

import "net/netip"

// trie — IPv6 prefikslar uchun ikkilik (radix) daraxt, eng uzun mos
// keluvchi prefiksni topish uchun.
//
// Nega daraxt, oddiy ro'yxat emas: `allowed_ips` da peer boshiga bir
// nechta prefiks bo'ladi va qidiruv HAR BIR PAKETDA bajariladi. Ro'yxat
// bo'yicha chiziqli qidiruv peerlar soni bilan sekinlashadi, daraxt esa
// prefiks uzunligiga bog'liq (maksimum 128 qadam).
//
// Bu tur o'zi qulflanmaydi — chaqiruvchi (Router) himoya qiladi.
type trie struct {
	root *trieNode
}

type trieNode struct {
	children [2]*trieNode

	// peer — shu tugunda prefiks tugasa, unga tegishli peer.
	peer *Peer

	// bits — shu tugunda tugaydigan prefiksning uzunligi.
	bits int
}

func newTrie() *trie {
	return &trie{root: &trieNode{bits: -1}}
}

// insert prefiksni peerga bog'laydi. Bir xil prefiks qayta kiritilsa
// eski egasi almashtiriladi.
func (t *trie) insert(prefix netip.Prefix, peer *Peer) {
	prefix = prefix.Masked()
	addr := prefix.Addr().As16()

	node := t.root
	for depth := range prefix.Bits() {
		next := bitAt(addr, depth)

		if node.children[next] == nil {
			node.children[next] = &trieNode{bits: -1}
		}
		node = node.children[next]
	}

	node.peer = peer
	node.bits = prefix.Bits()
}

// lookup manzil uchun eng uzun mos keluvchi prefiksning peerini qaytaradi.
//
// Eng uzun moslik muhim: `::/0` (exit-node) va `2a0e:1::/64` (tenant)
// bir vaqtda bo'lishi mumkin, va aniqrog'i g'olib chiqishi kerak.
func (t *trie) lookup(addr netip.Addr) *Peer {
	if !addr.Is6() {
		return nil
	}

	raw := addr.As16()
	node := t.root

	var best *Peer
	if node.peer != nil {
		best = node.peer // ::/0
	}

	for depth := range 128 {
		node = node.children[bitAt(raw, depth)]
		if node == nil {
			break
		}
		if node.peer != nil {
			best = node.peer
		}
	}

	return best
}

// removePeer shu peerga tegishli hamma yozuvni o'chiradi va bo'sh
// tugunlarni tozalaydi.
func (t *trie) removePeer(peer *Peer) {
	prune(t.root, peer)
}

// prune tugunni tozalaydi va u endi keraksiz bo'lsa true qaytaradi.
func prune(node *trieNode, peer *Peer) bool {
	if node == nil {
		return true
	}

	if node.peer == peer {
		node.peer = nil
		node.bits = -1
	}

	for i, child := range node.children {
		if prune(child, peer) {
			node.children[i] = nil
		}
	}

	return node.peer == nil && node.children[0] == nil && node.children[1] == nil
}

// bitAt manzilning `depth` pozitsiyasidagi bitini qaytaradi (0 yoki 1).
func bitAt(addr [16]byte, depth int) int {
	return int(addr[depth/8]>>(7-depth%8)) & 1
}
