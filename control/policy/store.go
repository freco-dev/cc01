package policy

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/netip"
	"os"
	"sync"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// Store kompilyatsiya qilingan qoidalarni saqlaydi va nodelarga
// beradi.
//
// ⚠️ Raft'da EMAS. Sabab: qoidalar manbai fayl (yoki keyinchalik
// AP), ya'ni ular har bir CP replikasida MUSTAQIL va bir xil
// hisoblanadi. Ularni jurnal orqali tarqatish bir xil ma'lumotni
// ikki marta ko'chirish bo'lardi.
//
// Buning sharti — kompilyatsiya deterministik bo'lishi. `Compile`
// aynan shunday va uni test qo'riqlaydi.
type Store struct {
	mu      sync.RWMutex
	doc     Document
	rules   []Rule
	version uint64

	// tagVersion — qoidalar qaysi registry holatidan
	// hisoblangani. Tag'lar nodelar bilan o'zgaradi, ya'ni ACL
	// o'zgarmasa ham qoidalar o'zgarishi mumkin.
	tagVersion uint64
	compiled   bool
}

func NewStore() *Store { return &Store{} }

// Set qoidalarni almashtiradi va yangi versiyani qaytaradi.
//
// Versiya MAZMUNDAN hisoblanadi, hisoblagich emas: bir xil hujjat
// qayta yuklansa versiya o'zgarmaydi va nodelar qoidalarga
// tegmaydi. Hisoblagich bo'lsa har `reload` da nodelar policy
// map'ini behuda qayta yozib, hukm keshini eskirtirardi.
func (s *Store) Set(rules []Rule) uint64 {
	version := versionOf(rules)

	s.mu.Lock()
	s.rules = rules
	s.version = version
	s.mu.Unlock()

	return version
}

// Rules — joriy qoidalar va ularning versiyasi.
func (s *Store) Rules() ([]Rule, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Rule, len(s.rules))
	copy(out, s.rules)
	return out, s.version
}

// Proto qoidalarni NetworkMap uchun tayyorlaydi.
func (s *Store) Proto() ([]*cc01v1.PolicyRule, uint64) {
	rules, version := s.Rules()

	out := make([]*cc01v1.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, &cc01v1.PolicyRule{
			Direction: uint32(rule.Direction),
			Prefix:    rule.Prefix.String(),
			Port:      uint32(rule.Port),
			Proto:     uint32(rule.Proto),
			Verdict:   uint32(rule.Verdict),
			RuleId:    rule.RuleID,
		})
	}

	return out, version
}

// versionOf qoidalar mazmunidan barqaror versiya hisoblaydi.
func versionOf(rules []Rule) uint64 {
	if len(rules) == 0 {
		return 0
	}

	hash := fnv.New64a()
	for _, rule := range rules {
		fmt.Fprintf(hash, "%d|%s|%d|%d|%d|%d\n",
			rule.Direction, rule.Prefix, rule.Port,
			rule.Proto, rule.Verdict, rule.RuleID)
	}

	// Nol "policy yo'q" degani, shuning uchun uni chetlab o'tamiz.
	version := hash.Sum64()
	if version == 0 {
		version = 1
	}
	return version
}

// LoadFile ACL faylini o'qiydi.
func LoadFile(path string) (Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("policy: faylni o'qish (%s): %w", path, err)
	}

	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Document{}, fmt.Errorf("policy: faylni o'qish (%s): %w", path, err)
	}

	// Hujjatni DARHOL tekshiramiz: yaroqsiz ACL ni saqlab qo'yib,
	// keyin har kompilyatsiyada xato berish nosozlikni
	// manbasidan uzoqlashtirardi.
	if _, err := Compile(doc, nil); err != nil {
		return Document{}, fmt.Errorf("policy: %s: %w", path, err)
	}

	return doc, nil
}

// SetDocument ACL ni almashtiradi va qayta kompilyatsiya qiladi.
func (s *Store) SetDocument(doc Document) {
	s.mu.Lock()
	s.doc = doc
	s.mu.Unlock()
}

// Refresh tag holati o'zgarganda qoidalarni qayta hisoblaydi.
//
// `tagVersion` — registry versiyasi. O'zgarmagan bo'lsa qayta
// kompilyatsiya qilinmaydi: u har bir NetworkMap uchun bajarilsa
// CP ni behuda yuklardi.
func (s *Store) Refresh(tags map[string][]netip.Prefix, tagVersion uint64) {
	s.mu.Lock()
	unchanged := s.compiled && s.tagVersion == tagVersion
	doc := s.doc
	s.mu.Unlock()

	if unchanged {
		return
	}

	rules, err := Compile(doc, tags)
	if err != nil {
		// Hujjat yuklashda tekshirilgan, ya'ni bu yerga xato
		// kelishi kutilmagan holat. Eski qoidalarni saqlab
		// qolamiz.
		return
	}

	version := versionOf(rules)

	s.mu.Lock()
	s.rules = rules
	s.version = version
	s.tagVersion = tagVersion
	s.compiled = true
	s.mu.Unlock()
}
