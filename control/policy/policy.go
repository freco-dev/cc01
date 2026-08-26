// Package policy deklarativ ACL ni nodega yuboriladigan qoidalarga
// aylantiradi (ARCHITECTURE.md §3.1.5).
//
// # Nega kompilyatsiya CP da
//
// Node hech qachon tag yoki guruhni o'zi yechmaydi. Sabab
// xavfsizlik emas, IZCHILLIK: agar har bir node tagni mustaqil
// yechsa, ular turli paytda turli natijaga kelardi va policy
// tarmoq bo'ylab bir xil bo'lmasdi. Buni tashxislash deyarli
// imkonsiz.
//
// Shuning uchun CP hamma narsani aniq prefikslarga aylantiradi va
// nodega tayyor ro'yxat yuboradi.
package policy

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Direction — qoida qaysi yo'nalishga tegishli.
type Direction uint32

const (
	Ingress Direction = 0
	Egress  Direction = 1
)

// Verdict — hukm.
type Verdict uint32

const (
	Drop  Verdict = 0
	Allow Verdict = 1
)

// Document — operator yozadigan ACL.
//
// JSON: YAML kutubxonasi qo'shilmadi, chunki bu fayl CP ga
// beriladigan yagona konfiguratsiya va uni AP (dashboard) generatsiya
// qiladigan bo'ladi — ya'ni u asosan mashina o'qiydigan format.
type Document struct {
	// Groups — nom → prefikslar. ACL da nom bilan murojaat
	// qilinadi, chiqishda esa prefikslar qoladi.
	Groups map[string][]string `json:"groups"`

	// Rules — qoidalar. Tartib AHAMIYATSIZ: aniqlik bo'yicha
	// tanlash yadroda bo'ladi (aniqroq port/protokol ustun).
	Rules []DocumentRule `json:"rules"`
}

// DocumentRule — bitta ACL yozuvi.
type DocumentRule struct {
	// Action — "allow" yoki "deny".
	Action string `json:"action"`

	// Src / Dst — guruh nomi yoki CIDR. Bittasi berilishi shart.
	//
	// Ikkalasi ham berilsa xato: guruh faqat bir tomondagi
	// prefiksdan olinadi va "manbadan maqsadga" qoidasini hozirgi
	// kalit sxemasi ifodalay olmaydi. Buni jimgina bir tomonga
	// aylantirish operatorni aldardi.
	Src string `json:"src,omitempty"`
	Dst string `json:"dst,omitempty"`

	// Proto — "tcp", "udp", "icmpv6" yoki raqam. Bo'sh = istalgan.
	Proto string `json:"proto,omitempty"`

	// Port — 0 yoki berilmagan = istalgan.
	Port uint16 `json:"port,omitempty"`

	// Comment — audit uchun; kompilyatsiyada tashlanadi.
	Comment string `json:"comment,omitempty"`
}

// Rule — kompilyatsiya natijasi: nodega yuboriladigan qoida.
type Rule struct {
	Direction Direction
	Prefix    netip.Prefix
	Port      uint16
	Proto     uint8
	Verdict   Verdict
	RuleID    uint32
}

// ErrInvalidDocument — ACL yaroqsiz.
var ErrInvalidDocument = errors.New("policy: ACL yaroqsiz")

// TagPrefix — ACL da tag'ga murojaat qilish uchun.
//
// Guruh nomlaridan ajratilgan: guruh statik ro'yxat, tag esa
// nodelarning JORIY holatidan kelib chiqadi va node qo'shilganda
// o'zgaradi.
const TagPrefix = "tag:"

// Compile ACL ni qoidalar ro'yxatiga aylantiradi.
//
// `tags` — tag → manzillar xaritasi (registry'dan). Bo'sh bo'lsa
// ACL da tag ishlatib bo'lmaydi.
//
// Natija DETERMINISTIK tartibda qaytadi: bir xil hujjat va bir xil
// tag holati har doim bir xil ro'yxat va bir xil identifikatorlar
// beradi. Aks holda har kompilyatsiyada versiya o'zgarib, nodelar
// qoidalarni behuda qayta qo'llardi.
func Compile(doc Document, tags map[string][]netip.Prefix) ([]Rule, error) {
	groups, err := resolveGroups(doc.Groups)
	if err != nil {
		return nil, err
	}

	var out []Rule

	for index, item := range doc.Rules {
		verdict, err := parseAction(item.Action)
		if err != nil {
			return nil, fmt.Errorf("%w: qoida %d: %v", ErrInvalidDocument, index+1, err)
		}

		direction, target, err := targetOf(item)
		if err != nil {
			return nil, fmt.Errorf("%w: qoida %d: %v", ErrInvalidDocument, index+1, err)
		}

		proto, err := parseProto(item.Proto)
		if err != nil {
			return nil, fmt.Errorf("%w: qoida %d: %v", ErrInvalidDocument, index+1, err)
		}

		prefixes, err := expand(target, groups, tags)
		if err != nil {
			return nil, fmt.Errorf("%w: qoida %d: %v", ErrInvalidDocument, index+1, err)
		}

		for _, prefix := range prefixes {
			out = append(out, Rule{
				Direction: direction,
				Prefix:    prefix,
				Port:      item.Port,
				Proto:     proto,
				Verdict:   verdict,
			})
		}
	}

	// Barqaror tartib va shundan keyin identifikatorlar.
	slices.SortFunc(out, compareRules)
	out = slices.CompactFunc(out, func(a, b Rule) bool { return compareRules(a, b) == 0 })

	for i := range out {
		out[i].RuleID = uint32(i + 1)
	}

	return out, nil
}

func compareRules(a, b Rule) int {
	if a.Direction != b.Direction {
		return int(a.Direction) - int(b.Direction)
	}
	if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
		return c
	}
	if a.Prefix.Bits() != b.Prefix.Bits() {
		return a.Prefix.Bits() - b.Prefix.Bits()
	}
	if a.Proto != b.Proto {
		return int(a.Proto) - int(b.Proto)
	}
	if a.Port != b.Port {
		return int(a.Port) - int(b.Port)
	}
	return int(a.Verdict) - int(b.Verdict)
}

// resolveGroups guruh nomlarini prefikslarga aylantiradi.
func resolveGroups(groups map[string][]string) (map[string][]netip.Prefix, error) {
	out := make(map[string][]netip.Prefix, len(groups))

	for _, name := range slices.Sorted(maps.Keys(groups)) {
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("%w: guruh nomi bo'sh", ErrInvalidDocument)
		}

		prefixes := make([]netip.Prefix, 0, len(groups[name]))
		for _, item := range groups[name] {
			prefix, err := parsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("%w: guruh %q: %v", ErrInvalidDocument, name, err)
			}
			prefixes = append(prefixes, prefix)
		}

		if len(prefixes) == 0 {
			return nil, fmt.Errorf("%w: guruh %q bo'sh", ErrInvalidDocument, name)
		}
		out[name] = prefixes
	}

	return out, nil
}

// expand tag, guruh nomi yoki CIDR ni prefikslarga aylantiradi.
func expand(
	target string,
	groups map[string][]netip.Prefix,
	tags map[string][]netip.Prefix,
) ([]netip.Prefix, error) {
	// Tag — nodelarning JORIY holatidan.
	//
	// Bo'sh natija xato EMAS: tag'ga ega node hali ulanmagan
	// bo'lishi mumkin va bu normal holat. Xato qaytarsak, birinchi
	// node ulanmaguncha butun ACL yaroqsiz bo'lardi.
	if name, ok := strings.CutPrefix(target, TagPrefix); ok {
		if name == "" {
			return nil, errors.New("tag nomi bo'sh")
		}
		return tags[target], nil
	}

	if prefixes, ok := groups[target]; ok {
		return prefixes, nil
	}

	prefix, err := parsePrefix(target)
	if err != nil {
		return nil, fmt.Errorf("%q — na tag, na guruh nomi, na CIDR: %v", target, err)
	}
	return []netip.Prefix{prefix}, nil
}

// parsePrefix CIDR yoki yakka manzilni prefiksga aylantiradi.
//
// Yakka manzil `/128` deb qabul qilinadi: operator ko'pincha aynan
// bitta nodeni nazarda tutadi va `/128` yozishni unutadi.
func parsePrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)

	if prefix, err := netip.ParsePrefix(value); err == nil {
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("faqat IPv6: %s", value)
		}
		return prefix.Masked(), nil
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if !addr.Is6() || addr.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("faqat IPv6: %s", value)
	}
	return netip.PrefixFrom(addr, 128), nil
}

func parseAction(action string) (Verdict, error) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow":
		return Allow, nil
	case "deny", "drop":
		return Drop, nil
	case "":
		return 0, errors.New("action ko'rsatilmagan (allow yoki deny)")
	default:
		return 0, fmt.Errorf("noma'lum action: %s", action)
	}
}

func targetOf(rule DocumentRule) (Direction, string, error) {
	src := strings.TrimSpace(rule.Src)
	dst := strings.TrimSpace(rule.Dst)

	switch {
	case src != "" && dst != "":
		return 0, "", errors.New(
			"src va dst birga berilmaydi: qoidalar bir tomondagi prefiks bo'yicha guruhlanadi")
	case src != "":
		return Ingress, src, nil
	case dst != "":
		return Egress, dst, nil
	default:
		return 0, "", errors.New("src yoki dst ko'rsating")
	}
}

func parseProto(name string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "any":
		return 0, nil
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "icmp", "icmpv6", "icmp6":
		return 58, nil
	}

	number, err := strconv.ParseUint(strings.TrimSpace(name), 10, 8)
	if err != nil {
		return 0, fmt.Errorf("noma'lum protokol: %s (tcp, udp, icmpv6 yoki raqam)", name)
	}
	return uint8(number), nil
}
