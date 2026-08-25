package policy

import (
	"fmt"
	"testing"
	"time"
)

// Faza 2 mezoni: 10k qoida 500 ms dan tez kompilyatsiya bo'lishi
// kerak (DEV_SPEC §14).
//
// Kompilyator saralaydi va takrorlarni tashlaydi — ya'ni O(n log n).
// O'lchov aynan shuni himoya qiladi: kimdir ichkariga tasodifan
// kvadratik qidiruv qo'shsa, bu test aytadi.
func TestCompile_TenThousandRules(t *testing.T) {
	const count = 10_000

	doc := Document{
		Groups: map[string][]string{},
		Rules:  make([]DocumentRule, 0, count),
	}

	// Har biri alohida guruh va port — eng og'ir holat: hech narsa
	// takrorlanmaydi, ya'ni dedup hech nimani qisqartirmaydi.
	for i := range count {
		group := fmt.Sprintf("g%d", i)
		doc.Groups[group] = []string{
			fmt.Sprintf("2a0e:1:%x:%x::/64", i>>16, i&0xffff),
		}
		doc.Rules = append(doc.Rules, DocumentRule{
			Action: "allow",
			Src:    group,
			Proto:  "tcp",
			Port:   uint16(1 + i%65535),
		})
	}

	start := time.Now()
	rules, err := Compile(doc, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(rules) != count {
		t.Fatalf("%d qoida chiqdi, %d kutilgan edi", len(rules), count)
	}

	t.Logf("%d qoida %v ichida kompilyatsiya bo'ldi", count,
		elapsed.Round(time.Millisecond))

	if elapsed > 500*time.Millisecond {
		t.Errorf("%v — 500 ms mezonidan sekin", elapsed)
	}
}
