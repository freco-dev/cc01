package registry

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// NetworkMapFor nodega yuboriladigan mapni quradi.
//
// `since` — klientda mavjud versiya:
//
//	0                  → to'liq map
//	jurnaldan eski     → to'liq map (delta hisoblab bo'lmaydi)
//	joriy versiyaga teng → bo'sh delta
//	aks holda          → faqat o'zgargan nodelar
//
// Tenant izolyatsiyasi: node faqat O'Z tenantidagi peerlarni ko'radi.
func (r *Registry) NetworkMapFor(nodeID string, since uint64) (*NetworkMap, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	self, ok := r.nodes[nodeID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNodeNotFound, nodeID)
	}

	result := &NetworkMap{
		Tenant:  self.Tenant,
		Version: r.version,
		Self:    self.Clone(),
		// GeneratedAt — REPLIKATSIYA qilinadigan holat emas, javob
		// metama'lumoti. Shuning uchun bu yerda devor soatini
		// o'qish xavfsiz: u jurnal orqali o'tmaydi.
		GeneratedAt: time.Now(),
		Relays:      slices.Clone(r.relays),
	}

	// Delta hisoblash mumkinmi? Jurnaldagi eng eski yozuv `since` dan
	// keyin bo'lsa, oradagi o'zgarishlar yo'qolgan — to'liq map kerak.
	//
	// `since == 0` — birinchi so'rov, u ham to'liq map oladi.
	oldest := r.oldestLoggedLocked()
	if since == 0 || (oldest > 0 && since < oldest-1) {
		result.Full = true
		result.Peers = r.peersLocked(self)
		return result, nil
	}

	if since >= r.version {
		// Klientda eng oxirgi holat bor.
		return result, nil
	}

	changed, removed := r.changesSinceLocked(self.Tenant, nodeID, since)
	result.Peers = changed
	result.Removed = removed

	return result, nil
}

// peersLocked tenantdagi barcha peerlarni qaytaradi (o'zidan tashqari).
func (r *Registry) peersLocked(self *Node) []*Node {
	members := r.tenantMembersLocked(self.Tenant)

	peers := make([]*Node, 0, max(len(members)-1, 0))
	for _, id := range members {
		if id == self.ID {
			continue
		}
		if node, ok := r.nodes[id]; ok {
			peers = append(peers, node.Clone())
		}
	}

	return peers
}

// changesSinceLocked `since` dan keyingi o'zgarishlarni yig'adi.
//
// Bitta node bir necha marta o'zgargan bo'lsa, u faqat BIR MARTA
// qaytariladi — klientga uning eng oxirgi holati kerak, oraliq
// holatlar emas.
func (r *Registry) changesSinceLocked(
	tenant, selfID string,
	since uint64,
) (changed []*Node, removed []string) {
	seen := make(map[string]struct{})

	// Teskari yo'nalishda yuramiz: har bir node uchun eng OXIRGI
	// o'zgarish hal qiluvchi bo'ladi.
	for i := len(r.log) - 1; i >= 0; i-- {
		entry := r.log[i]

		if entry.Version <= since {
			break
		}
		if entry.Tenant != tenant || entry.NodeID == selfID {
			continue
		}
		if _, done := seen[entry.NodeID]; done {
			continue
		}
		seen[entry.NodeID] = struct{}{}

		// Jurnaldagi turdan qat'i nazar, hozirgi haqiqiy holatga
		// qaraymiz: node o'chirilib, keyin qayta qo'shilgan bo'lishi
		// mumkin.
		if node, alive := r.nodes[entry.NodeID]; alive {
			changed = append(changed, node.Clone())
		} else {
			removed = append(removed, entry.NodeID)
		}
	}

	slices.SortFunc(changed, func(a, b *Node) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	slices.Sort(removed)

	return changed, removed
}

// Watch tenantdagi o'zgarishlar haqida xabar beruvchi kanal qaytaradi.
//
// Kanal yangi VERSIYA raqamini yuboradi, mapning o'zini emas: klient
// keyin `NetworkMapFor(nodeID, since)` chaqiradi. Shunda sekin
// kuzatuvchi uchun deltalarni buferlash kerak bo'lmaydi — u baribir
// eng oxirgi holatni oladi.
//
// Kanal `ctx` bekor qilinganda yopiladi.
func (r *Registry) Watch(ctx context.Context, tenant string) <-chan uint64 {
	notify := make(chan uint64, 1)

	r.mu.Lock()
	id := r.nextID
	r.nextID++
	r.watchers[id] = &watcher{tenant: tenant, notify: notify}
	r.mu.Unlock()

	go func() {
		<-ctx.Done()

		r.mu.Lock()
		delete(r.watchers, id)
		r.mu.Unlock()

		close(notify)
	}()

	return notify
}

// Watchers — faol kuzatuvchilar soni (diagnostika uchun).
func (r *Registry) Watchers() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.watchers)
}
