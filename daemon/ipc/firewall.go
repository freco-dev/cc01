package ipc

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/freco-dev/cc01/daemon/tcpolicy"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Firewall — eBPF policy boshqaruvi.
//
// `*tcpolicy.Filter` shu interfeysni qanoatlantiradi. Interfeys
// sifatida ajratilgani testlar uchun: haqiqiy filtr root, yadro va
// TUN qurilmasini talab qiladi, IPC mantiqini esa ularsiz sinash
// mumkin bo'lishi kerak.
type Firewall interface {
	IdentityFor(prefix netip.Prefix) (uint32, error)
	AddRule(rule tcpolicy.Rule) error
	RemoveByID(ruleID uint32) (tcpolicy.Rule, error)
	Rules() ([]tcpolicy.RuleStatus, error)
	Simulate(addr netip.Addr, port uint16, proto uint8, direction tcpolicy.Direction) (tcpolicy.Decision, error)
	SetEnforce(enforce bool) error
	Enforcing() bool
	Flush() (int, error)
	Generation() uint32
}

// FirewallProvider joriy filtrni qaytaradi.
//
// Funksiya sifatida berilgani muhim: IPC soketi mesh'dan OLDIN
// ochiladi (nosozlikni aynan kerak bo'lgan paytda ko'rish uchun),
// eBPF filtri esa TUN qurilmasi yaratilgandan KEYIN paydo bo'ladi.
// Qiymat sifatida saqlansa u har doim nil bo'lib qolardi.
type FirewallProvider func() Firewall

// FirewallService — FirewallService implementatsiyasi.
type FirewallService struct {
	cc01v1.UnimplementedFirewallServiceServer

	provider FirewallProvider

	// nextRuleID — chaqiruvchi ID bermaganda ishlatiladi.
	//
	// Yadroda qoidalar ID bo'yicha emas, kalit bo'yicha saqlanadi;
	// ID faqat audit va o'chirish uchun. Shuning uchun uni demon
	// beradi va u qayta ishga tushganda noldan boshlanadi — bu
	// muammo emas, chunki qoidalar ham yo'qoladi.
	nextRuleID atomic.Uint32
}

// ErrNoFirewall — eBPF filtri yuklanmagan.
var ErrNoFirewall = errors.New("ipc: eBPF filtri yuklanmagan")

func NewFirewallService(provider FirewallProvider) *FirewallService {
	service := &FirewallService{provider: provider}
	service.nextRuleID.Store(1)
	return service
}

// current joriy filtrni qaytaradi; yo'q bo'lsa nil.
func (s *FirewallService) current() Firewall {
	if s.provider == nil {
		return nil
	}
	return s.provider()
}

func (s *FirewallService) AddRule(
	_ context.Context,
	req *cc01v1.AddRuleRequest,
) (*cc01v1.AddRuleResponse, error) {
	firewall := s.current()
	if firewall == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNoFirewall.Error())
	}

	prefix, err := netip.ParsePrefix(req.GetPrefix())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"prefiks (%s): %v", req.GetPrefix(), err)
	}
	if req.GetPort() > 0xffff {
		return nil, status.Errorf(codes.InvalidArgument, "port: %d", req.GetPort())
	}
	if req.GetProto() > 0xff {
		return nil, status.Errorf(codes.InvalidArgument, "protokol: %d", req.GetProto())
	}
	if req.GetVerdict() == cc01v1.FirewallVerdict_FIREWALL_VERDICT_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "hukm ko'rsatilmagan")
	}

	identity, err := firewall.IdentityFor(prefix)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "guruh ajratish: %v", err)
	}

	ruleID := req.GetRuleId()
	if ruleID == 0 {
		ruleID = s.nextRuleID.Add(1) - 1
	}

	rule := tcpolicy.Rule{
		Direction: directionFromProto(req.GetDirection()),
		Identity:  identity,
		Port:      uint16(req.GetPort()),
		Proto:     uint8(req.GetProto()),
		Verdict:   verdictFromProto(req.GetVerdict()),
		RuleID:    ruleID,
	}

	if err := firewall.AddRule(rule); err != nil {
		return nil, status.Errorf(codes.Internal, "qoida qo'shish: %v", err)
	}

	return &cc01v1.AddRuleResponse{
		Rule: ruleToProto(tcpolicy.RuleStatus{Rule: rule, Prefix: prefix}),
	}, nil
}

func (s *FirewallService) DelRule(
	_ context.Context,
	req *cc01v1.DelRuleRequest,
) (*cc01v1.DelRuleResponse, error) {
	firewall := s.current()
	if firewall == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNoFirewall.Error())
	}

	rule, err := firewall.RemoveByID(req.GetRuleId())
	if err != nil {
		if errors.Is(err, tcpolicy.ErrRuleNotFound) {
			return nil, status.Errorf(codes.NotFound, "qoida %d topilmadi", req.GetRuleId())
		}
		return nil, status.Errorf(codes.Internal, "qoidani o'chirish: %v", err)
	}

	return &cc01v1.DelRuleResponse{
		Rule: ruleToProto(tcpolicy.RuleStatus{Rule: rule}),
	}, nil
}

func (s *FirewallService) ListRules(
	_ context.Context,
	req *cc01v1.ListRulesRequest,
) (*cc01v1.ListRulesResponse, error) {
	firewall := s.current()
	if firewall == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNoFirewall.Error())
	}

	rules, err := firewall.Rules()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "qoidalarni o'qish: %v", err)
	}

	filter := req.GetOnlyDirection()
	out := &cc01v1.ListRulesResponse{
		Rules:      make([]*cc01v1.FirewallRule, 0, len(rules)),
		Enforce:    firewall.Enforcing(),
		Generation: firewall.Generation(),
	}

	for _, rule := range rules {
		if filter != cc01v1.FirewallDirection_FIREWALL_DIRECTION_UNSPECIFIED &&
			directionToProto(rule.Direction) != filter {
			continue
		}
		out.Rules = append(out.Rules, ruleToProto(rule))
	}

	return out, nil
}

func (s *FirewallService) TestRule(
	_ context.Context,
	req *cc01v1.TestRuleRequest,
) (*cc01v1.TestRuleResponse, error) {
	firewall := s.current()
	if firewall == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNoFirewall.Error())
	}

	addr, err := netip.ParseAddr(req.GetAddr())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "manzil (%s): %v", req.GetAddr(), err)
	}

	decision, err := firewall.Simulate(addr,
		uint16(req.GetPort()), uint8(req.GetProto()),
		directionFromProto(req.GetDirection()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "simulyatsiya: %v", err)
	}

	out := &cc01v1.TestRuleResponse{
		Matched:  decision.Matched,
		Verdict:  verdictToProto(decision.Verdict),
		Identity: decision.Identity,
		Enforce:  firewall.Enforcing(),
	}
	if decision.Prefix.IsValid() {
		out.Prefix = decision.Prefix.String()
	}
	if decision.Matched {
		out.Rule = ruleToProto(tcpolicy.RuleStatus{
			Rule: decision.Rule, Prefix: decision.Prefix,
		})
	}

	return out, nil
}

func (s *FirewallService) SetMode(
	_ context.Context,
	req *cc01v1.SetModeRequest,
) (*cc01v1.SetModeResponse, error) {
	firewall := s.current()
	if firewall == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNoFirewall.Error())
	}

	if err := firewall.SetEnforce(req.GetEnforce()); err != nil {
		return nil, status.Errorf(codes.Internal, "rejimni o'zgartirish: %v", err)
	}
	return &cc01v1.SetModeResponse{Enforce: firewall.Enforcing()}, nil
}

func (s *FirewallService) Flush(
	_ context.Context,
	_ *cc01v1.FlushRequest,
) (*cc01v1.FlushResponse, error) {
	firewall := s.current()
	if firewall == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNoFirewall.Error())
	}

	removed, err := firewall.Flush()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "tozalash: %v", err)
	}
	return &cc01v1.FlushResponse{Removed: uint32(removed)}, nil
}

// ── Turlar orasidagi almashtirish ────────────────────────────────

func directionFromProto(d cc01v1.FirewallDirection) tcpolicy.Direction {
	if d == cc01v1.FirewallDirection_FIREWALL_DIRECTION_EGRESS {
		return tcpolicy.Egress
	}
	return tcpolicy.Ingress
}

func directionToProto(d tcpolicy.Direction) cc01v1.FirewallDirection {
	if d == tcpolicy.Egress {
		return cc01v1.FirewallDirection_FIREWALL_DIRECTION_EGRESS
	}
	return cc01v1.FirewallDirection_FIREWALL_DIRECTION_INGRESS
}

func verdictFromProto(v cc01v1.FirewallVerdict) tcpolicy.Verdict {
	if v == cc01v1.FirewallVerdict_FIREWALL_VERDICT_ALLOW {
		return tcpolicy.Allow
	}
	return tcpolicy.Drop
}

func verdictToProto(v tcpolicy.Verdict) cc01v1.FirewallVerdict {
	if v == tcpolicy.Allow {
		return cc01v1.FirewallVerdict_FIREWALL_VERDICT_ALLOW
	}
	return cc01v1.FirewallVerdict_FIREWALL_VERDICT_DROP
}

func ruleToProto(rule tcpolicy.RuleStatus) *cc01v1.FirewallRule {
	out := &cc01v1.FirewallRule{
		Direction: directionToProto(rule.Direction),
		Identity:  rule.Identity,
		Port:      uint32(rule.Port),
		Proto:     uint32(rule.Proto),
		Verdict:   verdictToProto(rule.Verdict),
		RuleId:    rule.RuleID,
		Hits:      rule.Hits,
	}
	if rule.Prefix.IsValid() {
		out.Prefix = rule.Prefix.String()
	}
	return out
}
