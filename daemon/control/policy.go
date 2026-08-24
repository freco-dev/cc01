package control

import (
	"errors"
	"net/netip"
	"sync"

	"github.com/freco-dev/cc01/daemon/tcpolicy"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// PolicyApplier CP dan kelgan qoidalarni qo'llaydi.
//
// `*tcpolicy.Filter` shu interfeysni qanoatlantiradi.
type PolicyApplier interface {
	IdentityFor(prefix netip.Prefix) (uint32, error)
	AddRule(rule tcpolicy.Rule) error
	RemoveRule(rule tcpolicy.Rule) error
	Rules() ([]tcpolicy.RuleStatus, error)
}

// ErrNoPolicyFilter — eBPF filtri yuklanmagan.
//
// `control` paketida e'lon qilingan, chunki aynan u bu holatni
// oddiy nosozlikdan ajratishi kerak: filtrsiz muhitda har bir
// NetworkMap uchun xato yozish logni to'ldirardi.
var ErrNoPolicyFilter = errors.New("control: eBPF policy filtri yuklanmagan")

// CPRuleIDBase — CP qoidalari shu raqamdan boshlanadi.
//
// Lokal (`cc01 firewall`) qoidalari undan PASTDA yashaydi.
// Ajratish kerak: CP qoidalari har yangilanishda to'liq
// almashtiriladi va bu paytda operator qo'lda qo'ygan qoidani
// o'chirib yuborish uni chalg'itardi — u qoidasi "o'z-o'zidan
// yo'qoldi" deb o'ylardi.
const CPRuleIDBase uint32 = 1_000_000

// policyState — oxirgi qo'llangan versiya.
type policyState struct {
	mu      sync.Mutex
	version uint64
	applied bool
}

// applyPolicy CP qoidalarini qo'llaydi.
//
// Qoidalar TO'LIQ almashtiriladi: CP diapazonidagi eskilari
// o'chiriladi, yangilari qo'yiladi. Delta hisoblash mumkin edi,
// lekin yarim qo'llangan policy butun trafikni kesib qo'yishi
// mumkin va bu xavf tejamdan kattaroq.
func (c *Client) applyPolicy(netmap *cc01v1.WatchNetworkMapResponse) {
	applier := c.cfg.Policy
	if applier == nil {
		return
	}

	version := netmap.GetPolicyVersion()

	// CP da policy umuman sozlanmagan — hech narsa qilmaymiz.
	// Nol versiya "qoida yo'q" degani va bu normal holat.
	if version == 0 && len(netmap.GetPolicy()) == 0 {
		return
	}

	c.policy.mu.Lock()
	defer c.policy.mu.Unlock()

	// Versiya o'zgarmagan bo'lsa tegmaymiz: har yangilanishda
	// policy map'ini qayta yozish hukm keshini behuda eskirtirardi.
	if c.policy.applied && c.policy.version == version {
		return
	}

	desired := make([]tcpolicy.Rule, 0, len(netmap.GetPolicy()))
	for _, item := range netmap.GetPolicy() {
		prefix, err := netip.ParsePrefix(item.GetPrefix())
		if err != nil {
			c.log.Warn("CP qoidasidagi prefiks yaroqsiz",
				"prefix", item.GetPrefix(), "rule", item.GetRuleId())
			continue
		}

		identity, err := applier.IdentityFor(prefix)
		if err != nil {
			c.log.Warn("guruh ajratilmadi", "prefix", prefix, "err", err)
			continue
		}

		desired = append(desired, tcpolicy.Rule{
			Direction: tcpolicy.Direction(item.GetDirection()),
			Identity:  identity,
			Port:      uint16(item.GetPort()),
			Proto:     uint8(item.GetProto()),
			Verdict:   tcpolicy.Verdict(item.GetVerdict()),
			RuleID:    CPRuleIDBase + item.GetRuleId(),
		})
	}

	if err := c.replaceCPRules(applier, desired); err != nil {
		if errors.Is(err, ErrNoPolicyFilter) {
			// Filtrsiz muhit — bu kutilgan holat va u har bir
			// NetworkMap da takrorlanadi. Xato darajasida
			// yozsak log to'lib ketardi.
			c.log.Debug("policy filtri yo'q, CP qoidalari qo'llanmadi")
			return
		}
		c.log.Error("CP qoidalarini qo'llash", "err", err)
		return
	}

	c.policy.version = version
	c.policy.applied = true

	c.log.Info("CP policy qo'llandi", "rules", len(desired), "version", version)
}

// replaceCPRules CP diapazonidagi qoidalarni almashtiradi.
func (c *Client) replaceCPRules(applier PolicyApplier, desired []tcpolicy.Rule) error {
	existing, err := applier.Rules()
	if err != nil {
		return err
	}

	// Avval qo'shamiz, keyin ortiqchasini o'chiramiz: teskari
	// tartibda almashtirish paytida ruxsat berilgan trafik uchun
	// qoidasiz oyna ochilardi va deny-by-default uni kesardi.
	wanted := make(map[uint32]struct{}, len(desired))
	for _, rule := range desired {
		wanted[rule.RuleID] = struct{}{}
		if err := applier.AddRule(rule); err != nil {
			return err
		}
	}

	for _, rule := range existing {
		if rule.RuleID < CPRuleIDBase {
			continue // lokal qoida — tegmaymiz
		}
		if _, keep := wanted[rule.RuleID]; keep {
			continue
		}
		if err := applier.RemoveRule(rule.Rule); err != nil {
			return err
		}
	}

	return nil
}
