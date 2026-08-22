package ipam

import (
	"context"
	"net/netip"
	"sync"
)

// State — IPAM ning to'liq holati.
//
// Butun holat bitta strukturada: u Raft FSM ga aynan shu ko'rinishda
// snapshot qilinadi.
type State struct {
	// Leases — ijara ID'si bo'yicha.
	Leases map[string]*Lease

	// ByPrefix — prefiks bo'yicha teskari indeks. Ikki marta
	// taqsimlashni oldini olish uchun eng muhim tuzilma.
	ByPrefix map[netip.Prefix]string

	// ByOwner — egasi bo'yicha: idempotent Allocate uchun.
	ByOwner map[ownerKey]string

	// ByParent — ota-prefiks bo'yicha band bolalar to'plami.
	//
	// Bu indeks bo'lmasa har bir taqsimlashda butun ijaralar ro'yxatini
	// skanerlash kerak bo'lardi. 100 000 tenantda (ARCHITECTURE.md §8)
	// bu ishlamaydi.
	ByParent map[netip.Prefix]map[netip.Prefix]struct{}
}

type ownerKey struct {
	Kind   LeaseKind
	Owner  string
	Parent netip.Prefix
}

func NewState() *State {
	return &State{
		Leases:   make(map[string]*Lease),
		ByPrefix: make(map[netip.Prefix]string),
		ByOwner:  make(map[ownerKey]string),
		ByParent: make(map[netip.Prefix]map[netip.Prefix]struct{}),
	}
}

// put ijara yozuvini barcha indekslar bilan birga qo'yadi.
func (s *State) put(lease *Lease) {
	s.Leases[lease.ID] = lease
	s.ByPrefix[lease.Prefix] = lease.ID
	s.ByOwner[ownerKey{lease.Kind, lease.Owner, lease.Parent}] = lease.ID

	children, ok := s.ByParent[lease.Parent]
	if !ok {
		children = make(map[netip.Prefix]struct{})
		s.ByParent[lease.Parent] = children
	}
	children[lease.Prefix] = struct{}{}
}

// drop ijarani va uning indekslarini o'chiradi.
func (s *State) drop(lease *Lease) {
	delete(s.Leases, lease.ID)

	if id, ok := s.ByPrefix[lease.Prefix]; ok && id == lease.ID {
		delete(s.ByPrefix, lease.Prefix)
	}

	key := ownerKey{lease.Kind, lease.Owner, lease.Parent}
	if id, ok := s.ByOwner[key]; ok && id == lease.ID {
		delete(s.ByOwner, key)
	}

	if children, ok := s.ByParent[lease.Parent]; ok {
		delete(children, lease.Prefix)
		if len(children) == 0 {
			delete(s.ByParent, lease.Parent)
		}
	}
}

// takenIn ota-prefiks ichidagi band prefikslarni qaytaradi.
//
// Karantindagilar ham BAND hisoblanadi: muddati tugagunicha prefiks
// qayta berilmaydi.
//
// Qaytarilgan xarita ichki indeksning O'ZI — chaqiruvchi uni
// o'zgartirmasligi kerak. Nusxa olinmagani ataylab: bu funksiya har
// bir taqsimlashda chaqiriladi.
func (s *State) takenIn(parent netip.Prefix) map[netip.Prefix]struct{} {
	return s.ByParent[parent]
}

// Store — IPAM holatini saqlaydi va o'zgarishlarni SERIALIZATSIYALAYDI.
//
// Ikki marta taqsimlash mumkin emasligi aynan shu yerda ta'minlanadi:
// `Update` ichidagi funksiya boshqa yozuvchilardan ajratilgan holda
// bajariladi, ya'ni tekshirish va yozish orasida bo'shliq qolmaydi.
//
// Raft implementatsiyasida `Update` — bu `raft.Apply`: o'zgarish
// jurnalga yoziladi, quorum tasdiqlaydi, keyin FSM ga qo'llanadi
// (ARCHITECTURE.md §3.1.6, ADR-006).
type Store interface {
	// Update holatni o'zgartiradi.
	//
	// KELISHUV: `fn` avval hamma tekshiruvni bajaradi, keyingina
	// holatga tegadi. Xato qaytarilganda o'zgarishlar avtomatik bekor
	// QILINMAYDI — butun holatni nusxalash O(N) bo'lgani uchun ataylab
	// shunday. Raft'da ham xuddi shunday: `Apply` allaqachon commit
	// qilingan buyruqni qo'llaydi, uni orqaga qaytarib bo'lmaydi.
	Update(ctx context.Context, fn func(*State) error) error

	// View holatni faqat o'qish uchun beradi. `fn` holatni
	// o'zgartirmasligi va undan olingan ko'rsatkichlarni saqlab
	// qolmasligi kerak.
	View(ctx context.Context, fn func(*State) error) error
}

// MemoryStore — bitta jarayondagi implementatsiya.
//
// Bir node uchun to'liq to'g'ri ishlaydi. Klaster uchun Raft
// implementatsiyasi kerak; Store interfeysi aynan shu almashtirishni
// oson qilish uchun ajratilgan.
type MemoryStore struct {
	mu    sync.Mutex
	state *State
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{state: NewState()}
}

func (m *MemoryStore) Update(ctx context.Context, fn func(*State) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return fn(m.state)
}

func (m *MemoryStore) View(ctx context.Context, fn func(*State) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return fn(m.state)
}
