package tcpolicy

import (
	"testing"
	"unsafe"
)

// Go tuzilmalari C dagilar bilan BAYT-BAYT mos kelishi shart.
//
// Mos kelmasa yadro xato BERMAYDI — u baytlarni boshqacha talqin
// qiladi va policy jimgina noto'g'ri hukm chiqaradi. Bu eng yomon
// nosozlik turi: filtr ishlayotgandek ko'rinadi.
//
// `bpf/include/cc01_maps.h`:
//
//	struct cc01_identity_key { __u32 prefixlen; __u8 addr[16]; };   // 20
//	struct cc01_policy_key   { __u32; __u16; __u8; __u8; };         // 8
//	struct cc01_policy_value { __u8; __u8[3]; __u32; __u64; };      // 16
//	struct cc01_policy_cfg   { __u32 ×3; __u16; __u8; __u8; }       // 16
func TestLayout_MatchesKernelStructs(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"cc01_identity_key", unsafe.Sizeof(identityKey{}), 20},
		{"cc01_policy_key", unsafe.Sizeof(policyKey{}), 8},
		{"cc01_policy_value", unsafe.Sizeof(policyValue{}), 16},
		{"cc01_policy_cfg", unsafe.Sizeof(configValue{}), 16},
		{"cc01_event", eventSize, 56},
	}

	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s o'lchami %d bayt, C tomonda %d — "+
				"bpf/include/cc01_maps.h bilan solishtiring", tc.name, tc.got, tc.want)
		}
	}
}

// Maydonlarning joylashuvi ham muhim: o'lcham to'g'ri, lekin tartib
// noto'g'ri bo'lsa test o'lcham bo'yicha o'tib ketardi.
func TestLayout_FieldOffsets(t *testing.T) {
	var key policyKey
	if offset := unsafe.Offsetof(key.Identity); offset != 0 {
		t.Errorf("Identity siljishi %d", offset)
	}
	if offset := unsafe.Offsetof(key.DPort); offset != 4 {
		t.Errorf("DPort siljishi %d, 4 kutilgan edi", offset)
	}
	if offset := unsafe.Offsetof(key.Proto); offset != 6 {
		t.Errorf("Proto siljishi %d, 6 kutilgan edi", offset)
	}
	// Yo'nalish ilgari `_pad` bo'lgan joyni egallaydi — o'lcham
	// o'zgarmasligi kerak.
	if offset := unsafe.Offsetof(key.Direction); offset != 7 {
		t.Errorf("Direction siljishi %d, 7 kutilgan edi", offset)
	}

	var value policyValue
	if offset := unsafe.Offsetof(value.RuleID); offset != 4 {
		t.Errorf("RuleID siljishi %d, 4 kutilgan edi", offset)
	}
	if offset := unsafe.Offsetof(value.Hits); offset != 8 {
		t.Errorf("Hits siljishi %d, 8 kutilgan edi", offset)
	}

	// LPM kalitida prefixlen BIRINCHI bo'lishi SHART: yadro uni
	// aynan shu joydan o'qiydi.
	var identity identityKey
	if offset := unsafe.Offsetof(identity.PrefixLen); offset != 0 {
		t.Errorf("PrefixLen siljishi %d — LPM buzilardi", offset)
	}
}

// Hisoblagich indekslari C dagi enum bilan mos kelishi kerak.
func TestLayout_StatIndexes(t *testing.T) {
	expected := []string{
		"CC01_PSTAT_TOTAL",
		"CC01_PSTAT_ALLOW",
		"CC01_PSTAT_DROP",
		"CC01_PSTAT_DROP_MALFORMED",
		"CC01_PSTAT_NOT_IPV6",
		"CC01_PSTAT_NO_RULE",
		"CC01_PSTAT_EVENT_LOST",
		"CC01_PSTAT_CT_HIT",
		"CC01_PSTAT_CT_MISS",
		"CC01_PSTAT_EGRESS_TOTAL",
		"CC01_PSTAT_EGRESS_DROP",
		"CC01_PSTAT_MSS_CLAMPED",
	}

	actual := map[int]string{
		StatTotal:         "CC01_PSTAT_TOTAL",
		StatAllow:         "CC01_PSTAT_ALLOW",
		StatDrop:          "CC01_PSTAT_DROP",
		StatDropMalformed: "CC01_PSTAT_DROP_MALFORMED",
		StatNotIPv6:       "CC01_PSTAT_NOT_IPV6",
		StatNoRule:        "CC01_PSTAT_NO_RULE",
		StatEventLost:     "CC01_PSTAT_EVENT_LOST",
		StatCacheHit:      "CC01_PSTAT_CT_HIT",
		StatCacheMiss:     "CC01_PSTAT_CT_MISS",
		StatEgressTotal:   "CC01_PSTAT_EGRESS_TOTAL",
		StatEgressDrop:    "CC01_PSTAT_EGRESS_DROP",
		StatMSSClamped:    "CC01_PSTAT_MSS_CLAMPED",
	}

	if statMax != len(expected) {
		t.Fatalf("statMax = %d, %d ta hisoblagich sanaldi", statMax, len(expected))
	}
	for index, name := range expected {
		if actual[index] != name {
			t.Errorf("indeks %d: Go'da %q, C'da %q", index, actual[index], name)
		}
	}
}

// Hukm qiymatlari C dagi CC01_VERDICT_* bilan mos kelishi kerak.
func TestVerdict_MatchesKernelValues(t *testing.T) {
	if Drop != 0 {
		t.Errorf("Drop = %d, C'da CC01_VERDICT_DROP = 0", Drop)
	}
	if Allow != 1 {
		t.Errorf("Allow = %d, C'da CC01_VERDICT_ALLOW = 1", Allow)
	}
	if Drop.String() != "drop" || Allow.String() != "allow" {
		t.Errorf("nomlar: %q / %q", Drop, Allow)
	}
}

func TestStats_AllCountersNamed(t *testing.T) {
	var stats Stats

	for index := range statMax {
		if name := stats.Name(index); name == "" || name == "noma'lum" {
			t.Errorf("hisoblagich %d nomsiz", index)
		}
	}
	if name := stats.Name(statMax); name != "noma'lum" {
		t.Errorf("chegaradan tashqari indeks %q qaytardi", name)
	}
}

// Yo'nalish qiymatlari C dagi CC01_DIR_* bilan mos kelishi kerak.
func TestDirection_MatchesKernelValues(t *testing.T) {
	if Ingress != 0 {
		t.Errorf("Ingress = %d, C'da CC01_DIR_INGRESS = 0", Ingress)
	}
	if Egress != 1 {
		t.Errorf("Egress = %d, C'da CC01_DIR_EGRESS = 1", Egress)
	}
	if Ingress.String() != "ingress" || Egress.String() != "egress" {
		t.Errorf("nomlar: %q / %q", Ingress, Egress)
	}
}

// MSS chegarasi overlay MTU'siga mos bo'lishi kerak.
//
// Hisob: 1280 (IPv6 minimumi) - 40 (IPv6) - 20 (TCP) = 1220.
func TestDefaultMSSClamp_FitsOverlayMTU(t *testing.T) {
	const (
		overlayMTU = 1280
		ipv6Header = 40
		tcpHeader  = 20
	)

	if want := uint16(overlayMTU - ipv6Header - tcpHeader); DefaultMSSClamp != want {
		t.Errorf("DefaultMSSClamp = %d, %d kutilgan edi", DefaultMSSClamp, want)
	}
}
