package policy

import (
	"errors"
	"net/netip"
	"testing"
)

func mustCompile(t *testing.T, doc Document) []Rule {
	t.Helper()

	rules, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return rules
}

// Guruh nomlari prefikslarga yechilishi kerak: node hech qachon
// tagni o'zi yechmaydi.
func TestCompile_ResolvesGroups(t *testing.T) {
	rules := mustCompile(t, Document{
		Groups: map[string][]string{
			"web": {"2a0e:1::1", "2a0e:1::2"},
		},
		Rules: []DocumentRule{
			{Action: "allow", Src: "web", Proto: "tcp", Port: 443},
		},
	})

	if len(rules) != 2 {
		t.Fatalf("%d ta qoida, 2 kutilgan edi (guruhda 2 ta a'zo)", len(rules))
	}
	for _, rule := range rules {
		if rule.Prefix.Bits() != 128 {
			t.Errorf("yakka manzil /128 bo'lishi kerak: %v", rule.Prefix)
		}
		if rule.Port != 443 || rule.Proto != 6 || rule.Verdict != Allow {
			t.Errorf("qoida noto'g'ri: %+v", rule)
		}
	}
}

// Bir xil hujjat har doim bir xil natija berishi kerak.
//
// Aks holda har kompilyatsiyada versiya o'zgarib, nodelar
// qoidalarni behuda qayta qo'llardi va hukm keshi eskirardi.
func TestCompile_IsDeterministic(t *testing.T) {
	doc := Document{
		Groups: map[string][]string{
			"a": {"2a0e:3::/64", "2a0e:1::/64"},
			"b": {"2a0e:2::/64"},
		},
		Rules: []DocumentRule{
			{Action: "allow", Src: "b", Proto: "udp"},
			{Action: "deny", Dst: "a", Port: 22},
			{Action: "allow", Src: "a", Proto: "tcp", Port: 443},
		},
	}

	first := mustCompile(t, doc)
	second := mustCompile(t, doc)

	if len(first) != len(second) {
		t.Fatalf("uzunliklar farq qildi: %d va %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("qoida %d farq qildi:\n  %+v\n  %+v", i, first[i], second[i])
		}
	}
}

// Takroriy qoidalar birlashtirilishi kerak.
func TestCompile_DeduplicatesRules(t *testing.T) {
	rules := mustCompile(t, Document{
		Rules: []DocumentRule{
			{Action: "allow", Src: "2a0e:1::/64", Proto: "tcp", Port: 443},
			{Action: "allow", Src: "2a0e:1::/64", Proto: "tcp", Port: 443},
		},
	})

	if len(rules) != 1 {
		t.Errorf("%d ta qoida, 1 kutilgan edi", len(rules))
	}
}

// Identifikatorlar ketma-ket va noyob bo'lishi kerak.
func TestCompile_AssignsUniqueIDs(t *testing.T) {
	rules := mustCompile(t, Document{
		Rules: []DocumentRule{
			{Action: "allow", Src: "2a0e:1::/64"},
			{Action: "allow", Src: "2a0e:2::/64"},
			{Action: "deny", Dst: "2a0e:3::/64"},
		},
	})

	seen := make(map[uint32]bool, len(rules))
	for _, rule := range rules {
		if rule.RuleID == 0 {
			t.Error("identifikator berilmadi")
		}
		if seen[rule.RuleID] {
			t.Errorf("identifikator takrorlandi: %d", rule.RuleID)
		}
		seen[rule.RuleID] = true
	}
}

// src va dst birga berilsa xato: "manbadan maqsadga" qoidasini
// hozirgi kalit sxemasi ifodalay olmaydi.
func TestCompile_RejectsBothDirections(t *testing.T) {
	_, err := Compile(Document{
		Rules: []DocumentRule{
			{Action: "allow", Src: "2a0e:1::/64", Dst: "2a0e:2::/64"},
		},
	})
	if !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("ErrInvalidDocument kutilgan edi: %v", err)
	}
}

func TestCompile_RejectsMalformed(t *testing.T) {
	cases := map[string]Document{
		"action yo'q": {Rules: []DocumentRule{{Src: "2a0e:1::/64"}}},
		"noma'lum action": {Rules: []DocumentRule{
			{Action: "maybe", Src: "2a0e:1::/64"}}},
		"yo'nalish yo'q": {Rules: []DocumentRule{{Action: "allow"}}},
		"noma'lum guruh": {Rules: []DocumentRule{
			{Action: "allow", Src: "bunday-guruh-yoq"}}},
		"IPv4": {Rules: []DocumentRule{
			{Action: "allow", Src: "192.0.2.0/24"}}},
		"noma'lum protokol": {Rules: []DocumentRule{
			{Action: "allow", Src: "2a0e:1::/64", Proto: "sctp-emas"}}},
		"bo'sh guruh": {
			Groups: map[string][]string{"x": {}},
			Rules:  []DocumentRule{{Action: "allow", Src: "x"}},
		},
	}

	for name, doc := range cases {
		if _, err := Compile(doc); err == nil {
			t.Errorf("%s: xato kutilgan edi", name)
		}
	}
}

// Yakka manzil /128 deb qabul qilinishi kerak: operator ko'pincha
// aynan bitta nodeni nazarda tutadi va /128 yozishni unutadi.
func TestCompile_SingleAddressBecomesHostPrefix(t *testing.T) {
	rules := mustCompile(t, Document{
		Rules: []DocumentRule{{Action: "allow", Src: "2a0e:1::5"}},
	})

	want := netip.MustParsePrefix("2a0e:1::5/128")
	if rules[0].Prefix != want {
		t.Errorf("prefiks %v, %v kutilgan edi", rules[0].Prefix, want)
	}
}

// Prefiks normallashtirilishi kerak: host bitlari qolsa yadro uni
// boshqacha talqin qilardi.
func TestCompile_MasksPrefix(t *testing.T) {
	rules := mustCompile(t, Document{
		Rules: []DocumentRule{{Action: "allow", Src: "2a0e:1::5/64"}},
	})

	want := netip.MustParsePrefix("2a0e:1::/64")
	if rules[0].Prefix != want {
		t.Errorf("prefiks %v, %v kutilgan edi", rules[0].Prefix, want)
	}
}

// Yo'nalish src/dst dan aniqlanishi kerak.
func TestCompile_DirectionFromTarget(t *testing.T) {
	rules := mustCompile(t, Document{
		Rules: []DocumentRule{
			{Action: "allow", Src: "2a0e:1::/64"},
			{Action: "allow", Dst: "2a0e:2::/64"},
		},
	})

	var ingress, egress int
	for _, rule := range rules {
		switch rule.Direction {
		case Ingress:
			ingress++
		case Egress:
			egress++
		}
	}
	if ingress != 1 || egress != 1 {
		t.Errorf("kirish=%d chiqish=%d, ikkalasidan bittadan kutilgan edi", ingress, egress)
	}
}

// Bo'sh hujjat xato emas: policy hali yozilmagan holat normal.
func TestCompile_EmptyDocument(t *testing.T) {
	rules, err := Compile(Document{})
	if err != nil {
		t.Fatalf("bo'sh hujjat xato berdi: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("%d ta qoida", len(rules))
	}
}
