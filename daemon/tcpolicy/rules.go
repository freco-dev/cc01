package tcpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/cilium/ebpf"
)

// Binding — manba/maqsad prefiksi va uning guruhi.
type Binding struct {
	Prefix   netip.Prefix
	Identity uint32
}

// RuleStatus — qoida va uning hisoblagichi.
type RuleStatus struct {
	Rule

	// Prefix — qoida qaysi prefiksga tegishli. Identity bo'yicha
	// teskari qidirib topiladi; topilmasa bo'sh qoladi.
	Prefix netip.Prefix

	// Hits — nechta paket shu qoida bo'yicha o'tgan yoki
	// tashlangan.
	Hits uint64
}

// firstIdentity — avtomatik ajratish shu raqamdan boshlanadi.
//
// Nol ATAYLAB tashlab ketiladi: u "noma'lum manba" degani va unga
// alohida ma'no yuklangan.
const firstIdentity uint32 = 1

// IdentityFor prefiksga guruh raqamini beradi, mavjud bo'lsa
// o'shani qaytaradi.
//
// Bu — kichik policy kompilyatori. Foydalanuvchi CIDR bilan
// ishlaydi, yadro esa raqam bilan; almashtirishni kimdir bajarishi
// kerak va uni CLI ga qoldirish har bir chaqiruvchida takrorlanardi.
func (f *Filter) IdentityFor(prefix netip.Prefix) (uint32, error) {
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return 0, fmt.Errorf("tcpolicy: faqat IPv6 prefiks: %v", prefix)
	}

	prefix = prefix.Masked()

	f.identityMu.Lock()
	defer f.identityMu.Unlock()

	if identity, ok := f.identities[prefix]; ok {
		return identity, nil
	}

	identity := f.nextIdentity
	if identity < firstIdentity {
		identity = firstIdentity
	}

	if err := f.setIdentityLocked(prefix, identity); err != nil {
		return 0, err
	}

	f.identities[prefix] = identity
	f.nextIdentity = identity + 1

	return identity, nil
}

// Bindings — barcha prefiks↔guruh bog'lanishlari.
func (f *Filter) Bindings() []Binding {
	f.identityMu.Lock()
	defer f.identityMu.Unlock()

	out := make([]Binding, 0, len(f.identities))
	for prefix, identity := range f.identities {
		out = append(out, Binding{Prefix: prefix, Identity: identity})
	}

	slices.SortFunc(out, func(a, b Binding) int {
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c
		}
		return a.Prefix.Bits() - b.Prefix.Bits()
	})
	return out
}

// prefixFor identity bo'yicha prefiksni topadi.
func (f *Filter) prefixFor(identity uint32) netip.Prefix {
	f.identityMu.Lock()
	defer f.identityMu.Unlock()

	for prefix, value := range f.identities {
		if value == identity {
			return prefix
		}
	}
	return netip.Prefix{}
}

// Rules yadrodagi barcha qoidalarni hisoblagichlari bilan
// qaytaradi.
func (f *Filter) Rules() ([]RuleStatus, error) {
	rules := f.collection.Maps["cc01_policy"]
	if rules == nil {
		return nil, errors.New("tcpolicy: policy map topilmadi")
	}

	var (
		key   policyKey
		value policyValue
		out   []RuleStatus
	)

	iter := rules.Iterate()
	for iter.Next(&key, &value) {
		out = append(out, RuleStatus{
			Rule: Rule{
				Direction: Direction(key.Direction),
				Identity:  key.Identity,
				Port:      key.DPort,
				Proto:     key.Proto,
				Verdict:   Verdict(value.Verdict),
				RuleID:    value.RuleID,
			},
			Prefix: f.prefixFor(key.Identity),
			Hits:   value.Hits,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("tcpolicy: qoidalarni ko'rib chiqish: %w", err)
	}

	// Barqaror tartib: qoidalar ro'yxati har chaqiruvda bir xil
	// ko'rinishi kerak, aks holda uni solishtirib bo'lmaydi.
	slices.SortFunc(out, func(a, b RuleStatus) int {
		if a.RuleID != b.RuleID {
			return int(a.RuleID) - int(b.RuleID)
		}
		if a.Identity != b.Identity {
			return int(a.Identity) - int(b.Identity)
		}
		return int(a.Port) - int(b.Port)
	})

	return out, nil
}

// RemoveByID qoidani CP dagi identifikatori bo'yicha o'chiradi.
//
// Map kaliti (identity, port, protokol, yo'nalish) — ID emas.
// Shuning uchun avval qidiriladi. Bu arzon: qoidalar soni minglar
// tartibida va o'chirish kam uchraydigan amal.
func (f *Filter) RemoveByID(ruleID uint32) (Rule, error) {
	rules, err := f.Rules()
	if err != nil {
		return Rule{}, err
	}

	for _, item := range rules {
		if item.RuleID == ruleID {
			return item.Rule, f.RemoveRule(item.Rule)
		}
	}

	return Rule{}, fmt.Errorf("tcpolicy: %w: %d", ErrRuleNotFound, ruleID)
}

// ErrRuleNotFound — qoida topilmadi.
var ErrRuleNotFound = errors.New("qoida topilmadi")

// Flush barcha qoidalarni va bog'lanishlarni o'chiradi.
//
// ⚠️ Deny-by-default siyosatida bu BUTUN TRAFIKNI kesadi. Chaqiruvchi
// buni tasdiqlashi kerak.
func (f *Filter) Flush() (int, error) {
	rules, err := f.Rules()
	if err != nil {
		return 0, err
	}

	var removed int
	for _, item := range rules {
		if err := f.RemoveRule(item.Rule); err != nil {
			return removed, err
		}
		removed++
	}

	for _, binding := range f.Bindings() {
		if err := f.RemoveIdentity(binding.Prefix); err != nil {
			return removed, err
		}
	}

	f.identityMu.Lock()
	f.identities = make(map[netip.Prefix]uint32)
	f.nextIdentity = firstIdentity
	f.identityMu.Unlock()

	return removed, nil
}

// Decision — simulyatsiya natijasi.
type Decision struct {
	// Identity — manba/maqsad qaysi guruhga tushdi.
	Identity uint32

	// Prefix — o'sha guruhning prefiksi; topilmasa bo'sh.
	Prefix netip.Prefix

	// Matched — qoida topildimi. false bo'lsa deny-by-default
	// ishlaydi.
	Matched bool

	// Rule — topilgan qoida.
	Rule Rule

	// Verdict — yakuniy hukm.
	Verdict Verdict
}

// Simulate paket qaysi qoidaga tushishini hisoblaydi.
//
// Yadroga paket yubormaydi: qidiruv tartibi shu yerda AYNAN
// takrorlanadi. Bu `cc01 firewall test` uchun — operator qoidani
// yozgandan keyin uni sinab ko'rishi kerak, ishlab chiqarish
// trafigini kutmasdan.
//
// ⚠️ Tartib C dagi `lookup_verdict` bilan bir xil bo'lishi shart.
// Farq qilsa buyruq yolg'on gapiradi va bu qoidani noto'g'ri
// yozishga olib keladi.
func (f *Filter) Simulate(addr netip.Addr, port uint16, proto uint8, direction Direction) (Decision, error) {
	if !addr.Is6() || addr.Is4In6() {
		return Decision{}, fmt.Errorf("tcpolicy: faqat IPv6 manzil: %v", addr)
	}

	identity, err := f.lookupIdentity(addr)
	if err != nil {
		return Decision{}, err
	}

	decision := Decision{
		Identity: identity,
		Prefix:   f.prefixFor(identity),
		Verdict:  Drop, // deny-by-default
	}

	// Aniqroqdan umumiyroqqa — C dagi tartib.
	candidates := []Rule{
		{Direction: direction, Identity: identity, Port: port, Proto: proto},
		{Direction: direction, Identity: identity, Port: 0, Proto: proto},
		{Direction: direction, Identity: identity, Port: 0, Proto: 0},
	}

	for _, candidate := range candidates {
		found, ok, err := f.lookupRule(candidate)
		if err != nil {
			return Decision{}, err
		}
		if ok {
			decision.Matched = true
			decision.Rule = found
			decision.Verdict = found.Verdict
			return decision, nil
		}
	}

	return decision, nil
}

// lookupIdentity manzil qaysi guruhga tushishini aniqlaydi.
//
// Yadro LPM trie'sidan so'raladi, xotiradagi nusxadan emas: shunda
// simulyatsiya HAQIQIY holatni ko'rsatadi.
func (f *Filter) lookupIdentity(addr netip.Addr) (uint32, error) {
	identities := f.collection.Maps["cc01_identity"]
	if identities == nil {
		return 0, errors.New("tcpolicy: identity map topilmadi")
	}

	key := identityKey{PrefixLen: 128}
	raw := addr.As16()
	copy(key.Addr[:], raw[:])

	var identity uint32
	if err := identities.Lookup(key, &identity); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return IdentityUnknown, nil
		}
		return 0, fmt.Errorf("tcpolicy: identity qidirish: %w", err)
	}
	return identity, nil
}

// lookupRule bitta qoidani qidiradi.
func (f *Filter) lookupRule(rule Rule) (Rule, bool, error) {
	rules := f.collection.Maps["cc01_policy"]
	if rules == nil {
		return Rule{}, false, errors.New("tcpolicy: policy map topilmadi")
	}

	key := policyKey{
		Identity:  rule.Identity,
		DPort:     rule.Port,
		Proto:     rule.Proto,
		Direction: uint8(rule.Direction),
	}

	var value policyValue
	if err := rules.Lookup(key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Rule{}, false, nil
		}
		return Rule{}, false, fmt.Errorf("tcpolicy: qoida qidirish: %w", err)
	}

	rule.Verdict = Verdict(value.Verdict)
	rule.RuleID = value.RuleID
	return rule, true, nil
}
