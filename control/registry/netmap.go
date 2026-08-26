package registry

import "time"

// NetworkMap — nodega yuboriladigan tarmoq ko'rinishi
// (ARCHITECTURE.md §3.1.2).
type NetworkMap struct {
	Tenant string

	// Version — monoton oshuvchi. Klient keyingi safar shu qiymatni
	// `since` sifatida yuboradi.
	Version uint64

	// Self — so'ragan nodening o'z yozuvi. U `Peers` ro'yxatida
	// BO'LMAYDI: node o'zi bilan sessiya qurmaydi.
	Self *Node

	// Peers — o'sha tenantdagi boshqa nodelar.
	Peers []*Node

	// Full — bu to'liq map (true) yoki delta (false).
	Full bool

	// Removed — deltada olib tashlangan nodelarning ID'lari.
	// To'liq mapda bo'sh bo'ladi.
	Removed []string

	GeneratedAt time.Time

	// Relays — mavjud relay tugunlari.
	//
	// Ular har bir javobda to'liq yuboriladi: ro'yxat kichik va
	// kamdan-kam o'zgaradi, ya'ni delta hisoblash ortiqcha
	// murakkablik bo'lardi.
	Relays []Relay
}

// Relay — trafikni uzatuvchi tugun (ARCHITECTURE.md §3.3.2).
type Relay struct {
	ID        string
	PublicKey PublicKey

	// Endpoint — underlay manzili. Klient unga to'g'ridan-to'g'ri
	// ulanadi.
	Endpoint netipAddrPort

	Region string

	// Priority — kichikroq qiymat yuqoriroq ustuvorlikni bildiradi.
	Priority uint32
}

// Empty — deltada hech qanday o'zgarish yo'qmi.
//
// Relay ro'yxati hisobga OLINMAYDI: u har bir javobda yuboriladi va
// o'zi bo'lib bo'sh deltani "to'la" qilib ko'rsatmasligi kerak.
func (m *NetworkMap) Empty() bool {
	return !m.Full && len(m.Peers) == 0 && len(m.Removed) == 0
}

// ChangeKind — o'zgarish turi.
type ChangeKind uint8

const (
	// ChangeUpsert — node qo'shildi yoki yangilandi.
	ChangeUpsert ChangeKind = iota

	// ChangeRemove — node ro'yxatdan chiqarildi.
	ChangeRemove
)

// change — versiya jurnalidagi bitta yozuv.
//
// Jurnal deltani hisoblash uchun kerak: klient "menda N bor" deydi,
// biz N dan keyingi yozuvlarni ko'rib chiqamiz.
type change struct {
	Version uint64
	Kind    ChangeKind
	Tenant  string
	NodeID  string
}
