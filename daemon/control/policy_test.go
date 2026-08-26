package control

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"github.com/freco-dev/cc01/daemon/tcpolicy"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// fakeApplier — haqiqiy eBPF filtri o'rniga.
type fakeApplier struct {
	rules      map[uint32]tcpolicy.RuleStatus
	identities map[netip.Prefix]uint32
	next       uint32
	fail       error
}

func newFakeApplier() *fakeApplier {
	return &fakeApplier{
		rules:      make(map[uint32]tcpolicy.RuleStatus),
		identities: make(map[netip.Prefix]uint32),
		next:       1,
	}
}

func (f *fakeApplier) IdentityFor(prefix netip.Prefix) (uint32, error) {
	if f.fail != nil {
		return 0, f.fail
	}
	if identity, ok := f.identities[prefix]; ok {
		return identity, nil
	}
	identity := f.next
	f.next++
	f.identities[prefix] = identity
	return identity, nil
}

func (f *fakeApplier) AddRule(rule tcpolicy.Rule) error {
	if f.fail != nil {
		return f.fail
	}
	f.rules[rule.RuleID] = tcpolicy.RuleStatus{Rule: rule}
	return nil
}

func (f *fakeApplier) RemoveRule(rule tcpolicy.Rule) error {
	if f.fail != nil {
		return f.fail
	}
	delete(f.rules, rule.RuleID)
	return nil
}

func (f *fakeApplier) Rules() ([]tcpolicy.RuleStatus, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	out := make([]tcpolicy.RuleStatus, 0, len(f.rules))
	for _, rule := range f.rules {
		out = append(out, rule)
	}
	return out, nil
}

func (f *fakeApplier) ruleIDs() []uint32 {
	out := make([]uint32, 0, len(f.rules))
	for id := range f.rules {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func policyClient(applier PolicyApplier) *Client {
	return &Client{
		cfg: Config{Policy: applier},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func netmapWith(version uint64, rules ...*cc01v1.PolicyRule) *cc01v1.WatchNetworkMapResponse {
	return &cc01v1.WatchNetworkMapResponse{
		Policy:        rules,
		PolicyVersion: version,
	}
}

func cpRule(id uint32, prefix string, port uint32, proto uint32) *cc01v1.PolicyRule {
	return &cc01v1.PolicyRule{
		Direction: 0,
		Prefix:    prefix,
		Port:      port,
		Proto:     proto,
		Verdict:   1,
		RuleId:    id,
	}
}

// CP qoidalari o'z diapazonida bo'lishi kerak.
func TestApplyPolicy_UsesCPRange(t *testing.T) {
	applier := newFakeApplier()
	client := policyClient(applier)

	client.applyPolicy(netmapWith(7, cpRule(1, "2a0e:1::/64", 443, 6)))

	ids := applier.ruleIDs()
	if len(ids) != 1 {
		t.Fatalf("%d ta qoida", len(ids))
	}
	if ids[0] != CPRuleIDBase+1 {
		t.Errorf("qoida ID %d, %d kutilgan edi", ids[0], CPRuleIDBase+1)
	}
}

// LOKAL qoidalar CP yangilanishida saqlanishi kerak.
//
// Aks holda operator qo'lda qo'ygan qoida "o'z-o'zidan yo'qolardi"
// va buni tushuntirish qiyin bo'lardi.
func TestApplyPolicy_KeepsLocalRules(t *testing.T) {
	applier := newFakeApplier()
	client := policyClient(applier)

	// Lokal qoida — CP diapazonidan pastda.
	local := tcpolicy.Rule{Identity: 99, RuleID: 5, Verdict: tcpolicy.Allow}
	if err := applier.AddRule(local); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	client.applyPolicy(netmapWith(1, cpRule(1, "2a0e:1::/64", 0, 0)))

	if _, ok := applier.rules[5]; !ok {
		t.Error("lokal qoida o'chirildi")
	}
}

// CP qoidalari TO'LIQ almashtirilishi kerak: eskilari ketadi.
func TestApplyPolicy_ReplacesCPRules(t *testing.T) {
	applier := newFakeApplier()
	client := policyClient(applier)

	client.applyPolicy(netmapWith(1,
		cpRule(1, "2a0e:1::/64", 0, 0),
		cpRule(2, "2a0e:2::/64", 0, 0)))

	if len(applier.rules) != 2 {
		t.Fatalf("%d ta qoida", len(applier.rules))
	}

	// Yangi versiyada faqat bittasi qoldi.
	client.applyPolicy(netmapWith(2, cpRule(1, "2a0e:1::/64", 0, 0)))

	ids := applier.ruleIDs()
	if len(ids) != 1 || ids[0] != CPRuleIDBase+1 {
		t.Errorf("qoidalar almashtirilmadi: %v", ids)
	}
}

// Versiya o'zgarmasa qoidalarga TEGILMASLIGI kerak: har
// yangilanishda policy map'ini qayta yozish hukm keshini behuda
// eskirtirardi.
func TestApplyPolicy_SkipsUnchangedVersion(t *testing.T) {
	applier := newFakeApplier()
	client := policyClient(applier)

	client.applyPolicy(netmapWith(9, cpRule(1, "2a0e:1::/64", 0, 0)))

	// Qo'lda o'zgartiramiz — qayta qo'llash uni tiklardi.
	delete(applier.rules, CPRuleIDBase+1)

	client.applyPolicy(netmapWith(9, cpRule(1, "2a0e:1::/64", 0, 0)))

	if len(applier.rules) != 0 {
		t.Error("o'zgarmagan versiya qayta qo'llandi")
	}
}

// Policy sozlanmagan bo'lsa hech narsa qilinmasligi kerak.
func TestApplyPolicy_IgnoresEmptyPolicy(t *testing.T) {
	applier := newFakeApplier()
	client := policyClient(applier)

	client.applyPolicy(netmapWith(0))

	if len(applier.rules) != 0 {
		t.Error("bo'sh policy uchun qoida qo'shildi")
	}
}

// Yaroqsiz prefiks butun to'plamni yiqitmasligi kerak: qolgan
// qoidalar baribir qo'llanishi kerak.
func TestApplyPolicy_SkipsMalformedRule(t *testing.T) {
	applier := newFakeApplier()
	client := policyClient(applier)

	client.applyPolicy(netmapWith(1,
		cpRule(1, "bunday-prefiks-yoq", 0, 0),
		cpRule(2, "2a0e:2::/64", 0, 0)))

	ids := applier.ruleIDs()
	if len(ids) != 1 || ids[0] != CPRuleIDBase+2 {
		t.Errorf("yaroqli qoida qo'llanmadi: %v", ids)
	}
}

// Filtr yo'q bo'lsa versiya YOZILMASLIGI kerak: filtr paydo
// bo'lganda qoidalar qo'llanishi kerak.
func TestApplyPolicy_DoesNotRecordVersionOnFailure(t *testing.T) {
	applier := newFakeApplier()
	applier.fail = ErrNoPolicyFilter
	client := policyClient(applier)

	client.applyPolicy(netmapWith(3, cpRule(1, "2a0e:1::/64", 0, 0)))

	if client.policy.applied {
		t.Fatal("xatoga qaramay versiya yozildi")
	}

	// Filtr paydo bo'ldi — endi qo'llanishi kerak.
	applier.fail = nil
	client.applyPolicy(netmapWith(3, cpRule(1, "2a0e:1::/64", 0, 0)))

	if len(applier.rules) != 1 {
		t.Errorf("filtr paydo bo'lgach qoidalar qo'llanmadi: %d", len(applier.rules))
	}
}

// Applier berilmagan bo'lsa yiqilmasligi kerak.
func TestApplyPolicy_NilApplier(t *testing.T) {
	client := policyClient(nil)
	client.applyPolicy(netmapWith(1, cpRule(1, "2a0e:1::/64", 0, 0)))
}

func TestErrNoPolicyFilter_IsComparable(t *testing.T) {
	if !errors.Is(ErrNoPolicyFilter, ErrNoPolicyFilter) {
		t.Error("xato solishtirib bo'lmaydi")
	}
}
