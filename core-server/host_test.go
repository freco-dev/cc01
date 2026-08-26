package main

import "testing"

// `Host` sarlavhasi portni ham olib yuradi (RFC 9110 §7.2), tunnel
// esa portsiz nom bilan ro'yxatga olinadi. Standart portda
// klientlar portni tushirib qoldiradi — shuning uchun bu xato
// faqat boshqa portda ko'rinadi va uzoq vaqt sezilmay qolishi
// mumkin edi.
func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"demo.cc01.uz":      "demo.cc01.uz",
		"demo.cc01.uz:8443": "demo.cc01.uz",
		"demo.cc01.uz:443":  "demo.cc01.uz",
		"DEMO.CC01.UZ:8443": "demo.cc01.uz",
		"  demo.cc01.uz  ":  "demo.cc01.uz",
		"[2a0e:1::1]:8443":  "[2a0e:1::1]",
		"[2a0e:1::1]":       "[2a0e:1::1]",
		"":                  "",
	}

	for input, want := range cases {
		if got := normalizeHost(input); got != want {
			t.Errorf("%q → %q, %q kutilgan edi", input, got, want)
		}
	}
}

// Qavssiz IPv6 `Host` da yaroqsiz, lekin uni port deb kesib
// tashlash manzilni buzardi — tegmasdan qoldiramiz.
func TestNormalizeHost_LeavesBareIPv6Alone(t *testing.T) {
	const bare = "2a0e:1::1"

	if got := normalizeHost(bare); got != bare {
		t.Errorf("%q → %q", bare, got)
	}
}
