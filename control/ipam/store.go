package ipam

import (
	"context"
	"net/netip"
	"sync"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
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
// buyruqlar qat'iy ketma-ketlikda qo'llanadi va `State.Apply` prefiks
// bandligini QAYTA tekshiradi.
//
// ⚠️ Interfeys ataylab BUYRUQ asosida, funksiya asosida emas.
//
// Ilgari u `Update(ctx, func(*State) error)` ko'rinishida edi va
// izohda "Raft implementatsiyasida bu `raft.Apply` bo'ladi" deb
// yozilgandi. Bu amalga oshmaydi: Raft jurnalga BAYTLAR yozadi va
// ularni har bir replikada qayta o'qiydi — funksiyani esa
// serializatsiya qilib bo'lmaydi. Bundan tashqari eski kod qarorni
// (tasodifiy prefiks, joriy vaqt) o'sha funksiya ichida qabul
// qilardi, ya'ni har bir replika boshqa natijaga kelardi.
//
// Endi qarorni LIDER qabul qiladi va TO'LIQ ANIQLANGAN buyruqni
// taklif qiladi; replikalar faqat qo'llaydi.
type Store interface {
	// Propose buyruqni jurnalga yozadi va qo'llaydi.
	//
	// Qaytarilgan ijara — nusxa. Sweep uchun ikkinchi qiymat
	// bo'shatilganlar sonini beradi.
	//
	// ErrPrefixTaken qaytishi normal: taklif qiluvchi holatning
	// nusxasi bo'yicha qaror qabul qilgan, jurnal esa buyruqlarni
	// ketma-ket qo'llaydi. Chaqiruvchi qayta urinadi.
	Propose(ctx context.Context, cmd *cc01v1.LeaseCommand) (*Lease, int, error)

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

func (m *MemoryStore) Propose(
	ctx context.Context,
	cmd *cc01v1.LeaseCommand,
) (*Lease, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return m.state.Apply(cmd)
}

func (m *MemoryStore) View(ctx context.Context, fn func(*State) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	return fn(m.state)
}

// Insert ijarani indekslari bilan birga holatga qo'yadi.
//
// Faqat snapshot'dan tiklash uchun: u yerda ijaralar allaqachon
// tasdiqlangan va qayta tekshirish kerak emas. Oddiy yo'l — Apply.
func (s *State) Insert(lease *Lease) { s.put(lease) }
