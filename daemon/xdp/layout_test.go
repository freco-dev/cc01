package xdp

import (
	"testing"
	"unsafe"
)

// Go tuzilmalari C dagilar bilan BAYT-BAYT mos kelishi shart.
//
// Mos kelmasa yadro xato BERMAYDI — u baytlarni shunchaki boshqacha
// talqin qiladi. Filtr jimgina noto'g'ri ishlaydi: masalan
// `expires_ns` o'rniga `hits` o'qilib, hamma yozuv darhol eskirgan
// deb hisoblanadi.
//
// `bpf/include/cc01_maps.h`:
//
//	struct cc01_config   { __u32 ×4; __u64; };                    // 24
//	struct cc01_block    { __u64 expires_ns; __u64 hits; };       // 16
//	struct cc01_rl_value { spin_lock; __u64 ×3; };                // 32
func TestLayout_MatchesKernelStructs(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"cc01_config", unsafe.Sizeof(configValue{}), 32},
		{"cc01_xdp_event", eventSize, 32},
		{"cc01_block", unsafe.Sizeof(blockValue{}), 16},
		{"cc01_rl_value", unsafe.Sizeof(rateLimitValue{}), 32},
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
	var block blockValue

	if offset := unsafe.Offsetof(block.ExpiresNS); offset != 0 {
		t.Errorf("ExpiresNS siljishi %d, 0 kutilgan edi", offset)
	}
	if offset := unsafe.Offsetof(block.Hits); offset != 8 {
		t.Errorf("Hits siljishi %d, 8 kutilgan edi", offset)
	}
}

// Statistika indekslari C dagi enum bilan mos kelishi kerak.
//
// Farq bo'lsa biz boshqa hisoblagichni o'qiymiz va raqamlar
// ishonchsiz bo'lib qoladi — buni sezish qiyin.
func TestLayout_StatIndexes(t *testing.T) {
	expected := map[int]string{
		0:  "CC01_STAT_TOTAL",
		1:  "CC01_STAT_PASS",
		2:  "CC01_STAT_DROP_BLOCKLIST",
		3:  "CC01_STAT_DROP_MALFORMED",
		4:  "CC01_STAT_NOT_IPV6",
		5:  "CC01_STAT_DROP_RATELIMIT",
		6:  "CC01_STAT_AUTO_BLOCKED",
		7:  "CC01_STAT_RL_MAP_FULL",
		8:  "CC01_STAT_DROP_AMPLIFY",
		9:  "CC01_STAT_REDIRECT",
		10: "CC01_STAT_EVENT_LOST",
	}

	actual := map[int]string{
		StatTotal:            "CC01_STAT_TOTAL",
		StatPass:             "CC01_STAT_PASS",
		StatDropBlocklist:    "CC01_STAT_DROP_BLOCKLIST",
		StatDropMalformed:    "CC01_STAT_DROP_MALFORMED",
		StatNotIPv6:          "CC01_STAT_NOT_IPV6",
		StatDropRateLimit:    "CC01_STAT_DROP_RATELIMIT",
		StatAutoBlocked:      "CC01_STAT_AUTO_BLOCKED",
		StatRateLimitMapFull: "CC01_STAT_RL_MAP_FULL",
		StatDropAmplify:      "CC01_STAT_DROP_AMPLIFY",
		StatRedirect:         "CC01_STAT_REDIRECT",
		StatEventLost:        "CC01_STAT_EVENT_LOST",
	}

	for index, name := range expected {
		if actual[index] != name {
			t.Errorf("indeks %d: Go'da %q, C'da %q", index, actual[index], name)
		}
	}

	if statMax != len(expected) {
		t.Errorf("statMax = %d, %d ta hisoblagich sanaldi", statMax, len(expected))
	}
}

// Har bir hisoblagichning nomi bo'lishi kerak — aks holda
// diagnostika chiqishida bo'sh qator paydo bo'lardi.
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

// Bosqich qiymatlari C dagi CC01_STAGE_* bilan mos kelishi kerak.
func TestStage_MatchesKernelValues(t *testing.T) {
	cases := map[Stage]uint8{
		StageBlocklist: 1,
		StageRateLimit: 2,
		StageAmplify:   3,
	}

	for stage, want := range cases {
		if uint8(stage) != want {
			t.Errorf("%v = %d, C'da %d", stage, stage, want)
		}
		if stage.String() == "noma'lum" {
			t.Errorf("bosqich %d nomsiz", stage)
		}
	}

	if Stage(99).String() != "noma'lum" {
		t.Error("noma'lum bosqich uchun nom qaytdi")
	}
}
