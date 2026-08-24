package ipc

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/freco-dev/cc01/daemon/tcpolicy"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeFirewall — haqiqiy eBPF filtri o'rniga.
//
// Haqiqiy filtr root, yadro va TUN qurilmasini talab qiladi; IPC
// mantiqini esa ularsiz sinash mumkin bo'lishi kerak.
type fakeFirewall struct {
	rules      map[uint32]tcpolicy.RuleStatus
	identities map[netip.Prefix]uint32
	next       uint32
	enforce    bool
	generation uint32
}

func newFakeFirewall() *fakeFirewall {
	return &fakeFirewall{
		rules:      make(map[uint32]tcpolicy.RuleStatus),
		identities: make(map[netip.Prefix]uint32),
		next:       1,
		enforce:    true,
	}
}

func (f *fakeFirewall) IdentityFor(prefix netip.Prefix) (uint32, error) {
	prefix = prefix.Masked()
	if identity, ok := f.identities[prefix]; ok {
		return identity, nil
	}
	identity := f.next
	f.next++
	f.identities[prefix] = identity
	return identity, nil
}

func (f *fakeFirewall) prefixFor(identity uint32) netip.Prefix {
	for prefix, value := range f.identities {
		if value == identity {
			return prefix
		}
	}
	return netip.Prefix{}
}

func (f *fakeFirewall) AddRule(rule tcpolicy.Rule) error {
	f.rules[rule.RuleID] = tcpolicy.RuleStatus{
		Rule: rule, Prefix: f.prefixFor(rule.Identity),
	}
	f.generation++
	return nil
}

func (f *fakeFirewall) RemoveByID(ruleID uint32) (tcpolicy.Rule, error) {
	rule, ok := f.rules[ruleID]
	if !ok {
		return tcpolicy.Rule{}, tcpolicy.ErrRuleNotFound
	}
	delete(f.rules, ruleID)
	f.generation++
	return rule.Rule, nil
}

func (f *fakeFirewall) Rules() ([]tcpolicy.RuleStatus, error) {
	out := make([]tcpolicy.RuleStatus, 0, len(f.rules))
	for _, rule := range f.rules {
		out = append(out, rule)
	}
	return out, nil
}

func (f *fakeFirewall) Simulate(
	addr netip.Addr, port uint16, proto uint8, direction tcpolicy.Direction,
) (tcpolicy.Decision, error) {
	for _, rule := range f.rules {
		if rule.Direction != direction {
			continue
		}
		if rule.Prefix.IsValid() && !rule.Prefix.Contains(addr) {
			continue
		}
		if rule.Port != 0 && rule.Port != port {
			continue
		}
		if rule.Proto != 0 && rule.Proto != proto {
			continue
		}
		return tcpolicy.Decision{
			Identity: rule.Identity, Prefix: rule.Prefix,
			Matched: true, Rule: rule.Rule, Verdict: rule.Verdict,
		}, nil
	}
	return tcpolicy.Decision{Verdict: tcpolicy.Drop}, nil
}

func (f *fakeFirewall) SetEnforce(enforce bool) error { f.enforce = enforce; return nil }
func (f *fakeFirewall) Enforcing() bool               { return f.enforce }
func (f *fakeFirewall) Generation() uint32            { return f.generation }

func (f *fakeFirewall) Flush() (int, error) {
	removed := len(f.rules)
	f.rules = make(map[uint32]tcpolicy.RuleStatus)
	f.identities = make(map[netip.Prefix]uint32)
	f.generation++
	return removed, nil
}

// startFirewall firewall xizmatini soket ustida ochadi.
func startFirewall(t *testing.T, firewall Firewall) cc01v1.FirewallServiceClient {
	provider := func() Firewall {
		if firewall == nil {
			return nil
		}
		return firewall
	}
	t.Helper()

	socket := shortSocket(t)
	quiet := slogDiscard()

	server, err := Listen(socket, NewService(&fakeBackend{up: true}, "test"), quiet,
		WithFirewall(provider))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go server.Serve()

	conn, err := Dial(socket)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
		_ = server.Close()
	})

	return cc01v1.NewFirewallServiceClient(conn)
}

// Qoida qo'shilganda guruh raqami AVTOMATIK ajratilishi kerak:
// operator CIDR bilan ishlaydi, yadro esa raqam bilan.
func TestFirewall_AddAllocatesIdentity(t *testing.T) {
	firewall := newFakeFirewall()
	client := startFirewall(t, firewall)

	response, err := client.AddRule(context.Background(), &cc01v1.AddRuleRequest{
		Direction: cc01v1.FirewallDirection_FIREWALL_DIRECTION_INGRESS,
		Prefix:    "2a0e:1::/64",
		Port:      443,
		Proto:     6,
		Verdict:   cc01v1.FirewallVerdict_FIREWALL_VERDICT_ALLOW,
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	rule := response.GetRule()
	if rule.GetIdentity() == 0 {
		t.Error("guruh ajratilmadi")
	}
	if rule.GetRuleId() == 0 {
		t.Error("qoida identifikatori berilmadi")
	}
	if rule.GetPrefix() != "2a0e:1::/64" {
		t.Errorf("prefiks %q", rule.GetPrefix())
	}
}

// Hukm ko'rsatilmasa qoida qabul qilinmasligi kerak: standart
// qiymat "taqiq" bo'lsa, operator xato yozib butun trafikni
// kesib qo'yardi.
func TestFirewall_RejectsMissingVerdict(t *testing.T) {
	client := startFirewall(t, newFakeFirewall())

	_, err := client.AddRule(context.Background(), &cc01v1.AddRuleRequest{
		Direction: cc01v1.FirewallDirection_FIREWALL_DIRECTION_INGRESS,
		Prefix:    "2a0e:1::/64",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("InvalidArgument kutilgan edi: %v", err)
	}
}

func TestFirewall_RejectsBadPrefix(t *testing.T) {
	client := startFirewall(t, newFakeFirewall())

	_, err := client.AddRule(context.Background(), &cc01v1.AddRuleRequest{
		Direction: cc01v1.FirewallDirection_FIREWALL_DIRECTION_INGRESS,
		Prefix:    "bunday-prefiks-yoq",
		Verdict:   cc01v1.FirewallVerdict_FIREWALL_VERDICT_ALLOW,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("InvalidArgument kutilgan edi: %v", err)
	}
}

// Mavjud bo'lmagan qoidani o'chirish NOT_FOUND berishi kerak.
func TestFirewall_DeleteUnknownRule(t *testing.T) {
	client := startFirewall(t, newFakeFirewall())

	_, err := client.DelRule(context.Background(), &cc01v1.DelRuleRequest{RuleId: 999})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("NotFound kutilgan edi: %v", err)
	}
}

// Ro'yxat rejimni va avlodni ham qaytarishi kerak: qoidalar bor,
// lekin dry-run bo'lsa ular QO'LLANMAYDI va operator buni bilishi
// shart.
func TestFirewall_ListReportsMode(t *testing.T) {
	firewall := newFakeFirewall()
	firewall.enforce = false
	client := startFirewall(t, firewall)

	if _, err := client.AddRule(context.Background(), &cc01v1.AddRuleRequest{
		Direction: cc01v1.FirewallDirection_FIREWALL_DIRECTION_INGRESS,
		Prefix:    "2a0e:1::/64",
		Verdict:   cc01v1.FirewallVerdict_FIREWALL_VERDICT_ALLOW,
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	response, err := client.ListRules(context.Background(), &cc01v1.ListRulesRequest{})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if response.GetEnforce() {
		t.Error("dry-run rejimi enforce deb ko'rsatildi")
	}
	if len(response.GetRules()) != 1 {
		t.Fatalf("%d ta qoida", len(response.GetRules()))
	}
}

// Yo'nalish bo'yicha filtrlash ishlashi kerak.
func TestFirewall_ListFiltersByDirection(t *testing.T) {
	client := startFirewall(t, newFakeFirewall())

	for _, direction := range []cc01v1.FirewallDirection{
		cc01v1.FirewallDirection_FIREWALL_DIRECTION_INGRESS,
		cc01v1.FirewallDirection_FIREWALL_DIRECTION_EGRESS,
	} {
		if _, err := client.AddRule(context.Background(), &cc01v1.AddRuleRequest{
			Direction: direction,
			Prefix:    "2a0e:1::/64",
			Verdict:   cc01v1.FirewallVerdict_FIREWALL_VERDICT_ALLOW,
		}); err != nil {
			t.Fatalf("AddRule: %v", err)
		}
	}

	response, err := client.ListRules(context.Background(), &cc01v1.ListRulesRequest{
		OnlyDirection: cc01v1.FirewallDirection_FIREWALL_DIRECTION_EGRESS,
	})
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(response.GetRules()) != 1 {
		t.Fatalf("%d ta qoida, 1 kutilgan edi", len(response.GetRules()))
	}
	if response.GetRules()[0].GetDirection() !=
		cc01v1.FirewallDirection_FIREWALL_DIRECTION_EGRESS {
		t.Error("filtr noto'g'ri yo'nalishni qaytardi")
	}
}

// Test buyrug'i rejimni ham qaytarishi kerak: dry-run'da hukm
// hisoblanadi, lekin qo'llanmaydi va natija chalg'ituvchi bo'lardi.
func TestFirewall_TestReportsEnforceMode(t *testing.T) {
	firewall := newFakeFirewall()
	firewall.enforce = false
	client := startFirewall(t, firewall)

	response, err := client.TestRule(context.Background(), &cc01v1.TestRuleRequest{
		Direction: cc01v1.FirewallDirection_FIREWALL_DIRECTION_INGRESS,
		Addr:      "2a0e:1::5",
		Port:      443,
		Proto:     6,
	})
	if err != nil {
		t.Fatalf("TestRule: %v", err)
	}
	if response.GetEnforce() {
		t.Error("dry-run rejimi enforce deb ko'rsatildi")
	}
	if response.GetMatched() {
		t.Error("qoidasiz holatda moslik topildi")
	}
	if response.GetVerdict() != cc01v1.FirewallVerdict_FIREWALL_VERDICT_DROP {
		t.Error("deny-by-default ishlamadi")
	}
}

// eBPF filtri yuklanmagan bo'lsa aniq xato berilishi kerak.
func TestFirewall_ReportsMissingFilter(t *testing.T) {
	client := startFirewall(t, nil)

	_, err := client.ListRules(context.Background(), &cc01v1.ListRulesRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("FailedPrecondition kutilgan edi: %v", err)
	}

	// Xato sababni aytishi kerak, aks holda operator nima
	// qilishini bilmasdi.
	if !strings.Contains(status.Convert(err).Message(), "yuklanmagan") {
		t.Errorf("xato sababni tushuntirmaydi: %v", err)
	}
}

func TestFirewall_Flush(t *testing.T) {
	firewall := newFakeFirewall()
	client := startFirewall(t, firewall)

	for range 3 {
		if _, err := client.AddRule(context.Background(), &cc01v1.AddRuleRequest{
			Direction: cc01v1.FirewallDirection_FIREWALL_DIRECTION_INGRESS,
			Prefix:    "2a0e:1::/64",
			Verdict:   cc01v1.FirewallVerdict_FIREWALL_VERDICT_ALLOW,
		}); err != nil {
			t.Fatalf("AddRule: %v", err)
		}
	}

	response, err := client.Flush(context.Background(), &cc01v1.FlushRequest{})
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if response.GetRemoved() != 3 {
		t.Errorf("%d ta o'chirildi, 3 kutilgan edi", response.GetRemoved())
	}
}

// Rejimni almashtirish ishlashi kerak.
func TestFirewall_SetMode(t *testing.T) {
	firewall := newFakeFirewall()
	client := startFirewall(t, firewall)

	response, err := client.SetMode(context.Background(), &cc01v1.SetModeRequest{
		Enforce: false,
	})
	if err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	if response.GetEnforce() {
		t.Error("dry-run ga o'tmadi")
	}
	if firewall.enforce {
		t.Error("filtr rejimi o'zgarmadi")
	}
}
