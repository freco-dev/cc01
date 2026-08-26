package registry

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNodeNotFound — bunday node ro'yxatda yo'q.
	ErrNodeNotFound = errors.New("registry: node topilmadi")

	// ErrTenantRequired — tenant ko'rsatilmagan.
	ErrTenantRequired = errors.New("registry: tenant ko'rsatilmagan")

	// ErrKeyRequired — public kalit berilmagan.
	ErrKeyRequired = errors.New("registry: public kalit berilmagan")
)

const (
	// DefaultTTL — heartbeat kelmasa node shuncha vaqtdan keyin
	// offline hisoblanadi.
	DefaultTTL = 90 * time.Second

	// DefaultLogLimit — versiya jurnalida nechta yozuv saqlanadi.
	//
	// Jurnal to'lganda eski yozuvlar tashlanadi va juda orqada qolgan
	// klientga to'liq map yuboriladi. Chegara kerak: aks holda uzoq
	// ishlagan CP xotirasi cheksiz o'sardi.
	DefaultLogLimit = 4096
)

// Registry — nodelar ro'yxati va versiya jurnali.
//
// ⚠️ Bu Raft HOLAT MASHINASINING bir qismi (ARCHITECTURE.md
// §3.1.6). O'zgartirish YAGONA yo'li — `Apply`, ya'ni protobuf
// buyrug'i orqali; qolgan metodlar faqat o'qiydi. Shu sababli
// vaqt ham, TTL ham bu yerda saqlanmaydi: ular buyruqda keladi va
// liderda hal qilinadi.
//
// Har bir CP replikasi o'z nusxasini ushlaydi va bir xil jurnalni
// qo'llaydi — shuning uchun follower ham to'liq NetworkMap bera
// oladi va lider almashganda peerlar yo'qolmaydi.
type Registry struct {
	mu sync.RWMutex

	nodes map[string]*Node

	// byTenant — tenant bo'yicha node ID'lari. NetworkMap qurishda
	// hamma nodelarni skanerlamaslik uchun.
	byTenant map[string]map[string]struct{}

	// version — monoton hisoblagich. Har bir o'zgarishda oshadi.
	version uint64

	// log — o'zgarishlar jurnali, versiya bo'yicha o'sish tartibida.
	log []change

	logLimit int

	// watchers — o'zgarishlardan xabardor qilinadigan kanallar.
	watchers map[int]*watcher
	nextID   int

	// relays — mavjud relay tugunlari. Ular nodelardan mustaqil:
	// operator tomonidan sozlanadi, dinamik ro'yxatdan o'tmaydi.
	relays []Relay
}

type watcher struct {
	tenant string
	notify chan uint64
}

// Options — registry sozlamalari.
//
// ⚠️ Bu yerda VAQT ham, TTL ham yo'q. Ular buyruqdan keladi:
// registry Raft holat mashinasining bir qismi va `Apply` ichida
// `time.Now()` ni o'qish replikalarni ajratib yuborardi
// (ARCHITECTURE.md §3.1.6, ADR-006).
type Options struct {
	// LogLimit — 0 bo'lsa DefaultLogLimit.
	LogLimit int
}

func New(opts Options) *Registry {
	limit := opts.LogLimit
	if limit <= 0 {
		limit = DefaultLogLimit
	}

	return &Registry{
		nodes:    make(map[string]*Node),
		byTenant: make(map[string]map[string]struct{}),
		logLimit: limit,
		watchers: make(map[int]*watcher),
	}
}

// Registration — node ro'yxatdan o'tish so'rovi.
type Registration struct {
	PublicKey PublicKey
	Tenant    string
	Hostname  string
	Addresses []netipPrefix
	Endpoints []netipAddrPort
	Tags      []string
	RelayHome string
}

// Register nodeni ro'yxatga oladi yoki mavjudini yangilaydi.
//
// Idempotent: bir xil kalit bilan qayta chaqirilsa yangi node
// yaratilmaydi. Node ID kalitdan hosil bo'lgani uchun uni klient
// tanlay olmaydi.
func (r *Registry) applyRegister(
	now time.Time, ttl time.Duration, reg Registration,
) (*Node, error) {
	if reg.Tenant == "" {
		return nil, ErrTenantRequired
	}
	if (reg.PublicKey == PublicKey{}) {
		return nil, ErrKeyRequired
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	id := NodeID(reg.PublicKey)

	node, existing := r.nodes[id]
	if !existing {
		node = &Node{ID: id, PublicKey: reg.PublicKey, CreatedAt: now}
	}

	// Tenant o'zgarishi — nodeni eski tenantdan chiqarish kerak.
	if existing && node.Tenant != reg.Tenant {
		r.detachLocked(node)
	}

	node.Tenant = reg.Tenant
	node.Hostname = reg.Hostname
	node.Addresses = slices.Clone(reg.Addresses)
	node.Endpoints = slices.Clone(reg.Endpoints)
	node.Tags = slices.Clone(reg.Tags)
	node.RelayHome = reg.RelayHome
	node.LastSeen = now
	node.ExpiresAt = now.Add(ttl)

	r.nodes[id] = node
	r.attachLocked(node)
	r.recordLocked(ChangeUpsert, node.Tenant, id)

	return node.Clone(), nil
}

// Heartbeat nodening TTL'ini uzaytiradi va endpointlarini yangilaydi.
//
// Endpointlar o'zgarmagan bo'lsa versiya OSHIRILMAYDI: har 30 sekundlik
// heartbeat butun tenantga delta yuborishga sabab bo'lmasligi kerak.
func (r *Registry) applyHeartbeat(
	now time.Time, ttl time.Duration, nodeID string, endpoints []netipAddrPort,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	node, ok := r.nodes[nodeID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNodeNotFound, nodeID)
	}

	node.LastSeen = now
	node.ExpiresAt = now.Add(ttl)

	if endpoints != nil && !slices.Equal(node.Endpoints, endpoints) {
		node.Endpoints = slices.Clone(endpoints)
		r.recordLocked(ChangeUpsert, node.Tenant, nodeID)
	}

	return nil
}

// Unregister nodeni ro'yxatdan chiqaradi.
func (r *Registry) applyUnregister(nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	node, ok := r.nodes[nodeID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNodeNotFound, nodeID)
	}

	r.detachLocked(node)
	delete(r.nodes, nodeID)
	r.recordLocked(ChangeRemove, node.Tenant, nodeID)

	return nil
}

// Node bitta nodeni qaytaradi.
func (r *Registry) Node(nodeID string) (*Node, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	node, ok := r.nodes[nodeID]
	return node.Clone(), ok
}

// SetRelays mavjud relay ro'yxatini o'rnatadi.
//
// ⚠️ Relaylar REPLIKATSIYA QILINMAYDI va bu ataylab: har bir CP
// o'zining ichki relay'ini e'lon qiladi (`cmd/cc01-cp/relay.go`).
// Ularni jurnalga yozsak, replikalar bir-birining manzilini
// almashtirib turardi va klient o'zi ulanmagan CP ning relay'ini
// olardi.
//
// Ro'yxat o'zgarsa versiya oshadi va kuzatuvchilar xabardor qilinadi:
// nodelar yangi relayga ulanishi kerak.
func (r *Registry) SetRelays(relays []Relay) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if slices.EqualFunc(r.relays, relays, sameRelay) {
		return
	}

	r.relays = slices.Clone(relays)

	// Relay o'zgarishi HAMMA tenantga tegishli.
	r.version++
	for _, w := range r.watchers {
		select {
		case w.notify <- r.version:
		default:
		}
	}
}

func sameRelay(a, b Relay) bool {
	return a.ID == b.ID && a.PublicKey == b.PublicKey &&
		a.Endpoint == b.Endpoint && a.Region == b.Region && a.Priority == b.Priority
}

// Relays — joriy relay ro'yxati.
func (r *Registry) Relays() []Relay {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.relays)
}

// Version — joriy monoton versiya.
func (r *Registry) Version() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// applyExpire muddati o'tgan nodelarni ro'yxatdan chiqaradi va
// nechtasi chiqarilganini qaytaradi.
//
// ⚠️ Chiqariladiganlar SARALANADI. Go'da map bo'ylab yurish tartibi
// tasodifiy, `recordLocked` esa har chaqiruvda versiyani oshiradi —
// ya'ni saralamasak, har bir replikada bir xil versiya BOSHQA
// nodega tegib qolardi va holat jimgina ajralib ketardi.
func (r *Registry) applyExpire(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	var expired []string
	for id, node := range r.nodes {
		if !node.Online(now) {
			expired = append(expired, id)
		}
	}
	slices.Sort(expired)

	for _, id := range expired {
		node := r.nodes[id]
		r.detachLocked(node)
		delete(r.nodes, id)
		r.recordLocked(ChangeRemove, node.Tenant, id)
	}

	return len(expired)
}

// ─────────────────────── ichki yordamchilar ───────────────────────

func (r *Registry) attachLocked(node *Node) {
	members, ok := r.byTenant[node.Tenant]
	if !ok {
		members = make(map[string]struct{})
		r.byTenant[node.Tenant] = members
	}
	members[node.ID] = struct{}{}
}

func (r *Registry) detachLocked(node *Node) {
	members, ok := r.byTenant[node.Tenant]
	if !ok {
		return
	}
	delete(members, node.ID)
	if len(members) == 0 {
		delete(r.byTenant, node.Tenant)
	}
}

// recordLocked versiyani oshiradi, jurnalga yozadi va kuzatuvchilarni
// xabardor qiladi.
func (r *Registry) recordLocked(kind ChangeKind, tenant, nodeID string) {
	r.version++

	r.log = append(r.log, change{
		Version: r.version,
		Kind:    kind,
		Tenant:  tenant,
		NodeID:  nodeID,
	})

	// Jurnal chegaradan oshsa eng eskilarini tashlaymiz. Juda orqada
	// qolgan klient to'liq map oladi — bu to'g'ri va xavfsiz.
	if len(r.log) > r.logLimit {
		r.log = slices.Delete(r.log, 0, len(r.log)-r.logLimit)
	}

	r.notifyLocked(tenant, r.version)
}

func (r *Registry) notifyLocked(tenant string, version uint64) {
	for _, w := range r.watchers {
		if w.tenant != tenant {
			continue
		}
		select {
		case w.notify <- version:
		default:
			// Kuzatuvchi hali oldingi xabarni o'qimagan — yangisini
			// tashlaymiz. U baribir `since` bilan so'raydi va eng
			// oxirgi holatni oladi, ya'ni hech narsa yo'qolmaydi.
		}
	}
}

// oldestLoggedLocked jurnaldagi eng eski versiyani qaytaradi.
func (r *Registry) oldestLoggedLocked() uint64 {
	if len(r.log) == 0 {
		return 0
	}
	return r.log[0].Version
}

// tenantMembersLocked tenantdagi node ID'larini qaytaradi.
func (r *Registry) tenantMembersLocked(tenant string) []string {
	members, ok := r.byTenant[tenant]
	if !ok {
		return nil
	}
	return slices.Sorted(maps.Keys(members))
}

// Snapshot holatning nusxasini beradi (Raft snapshot uchun).
//
// Versiya ham qaytariladi: u replikatsiya qilinadigan holatning
// bir qismi. Tiklashda nolga tushib qolsa, klientlar allaqachon
// ko'rgan versiyani qaytadan olib, delta sinxronizatsiyasi
// buzilardi.
func (r *Registry) Snapshot() ([]*Node, uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nodes := make([]*Node, 0, len(r.nodes))
	for _, node := range r.nodes {
		nodes = append(nodes, node.Clone())
	}

	// Snapshot fayli baytma-bayt bir xil bo'lishi uchun saralaymiz.
	// Zarur emas, lekin ikki replikaning snapshot'ini solishtirish
	// nosozlik qidirishda juda qulay.
	slices.SortFunc(nodes, func(a, b *Node) int {
		return strings.Compare(a.ID, b.ID)
	})

	return nodes, r.version
}

// Restore snapshot'dan holatni tiklaydi.
//
// O'zgarishlar jurnali TIKLANMAYDI: u faqat delta hisoblash uchun
// va bo'sh jurnal klientni to'liq map olishga majbur qiladi — bu
// to'g'ri zaxira yo'l.
func (r *Registry) Restore(nodes []*Node, version uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.nodes = make(map[string]*Node, len(nodes))
	r.byTenant = make(map[string]map[string]struct{})
	r.log = nil
	r.version = version

	for _, node := range nodes {
		clone := node.Clone()
		r.nodes[clone.ID] = clone
		r.attachLocked(clone)
	}
}

// TagIndex tenant ichidagi tag → manzillar xaritasini qaytaradi.
//
// Policy kompilyatori uchun: ACL da `tag:web` yozilganda u shu
// tag'ga ega nodelarning MANZILLARIGA aylanadi.
//
// Manzillar tag bilan birga o'zgaradi — node qo'shilganda,
// ketganda yoki tag'i almashganda. Shuning uchun kompilyatsiya
// registry versiyasiga bog'lanadi.
func (r *Registry) TagIndex(tenant string) map[string][]netipPrefix {
	r.mu.RLock()
	defer r.mu.RUnlock()

	index := make(map[string][]netipPrefix)

	for _, nodeID := range r.tenantMembersLocked(tenant) {
		node, ok := r.nodes[nodeID]
		if !ok {
			continue
		}
		for _, tag := range node.Tags {
			index[tag] = append(index[tag], node.Addresses...)
		}
	}

	// Barqaror tartib: kompilyatsiya deterministik bo'lishi kerak,
	// aks holda bir xil holat har safar boshqa versiya berardi va
	// nodelar qoidalarni behuda qayta qo'llardi.
	for tag := range index {
		slices.SortFunc(index[tag], func(a, b netipPrefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})
		index[tag] = slices.Compact(index[tag])
	}

	return index
}
