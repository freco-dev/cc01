//go:build !linux

package tcpolicy

// isLayer3 faqat Linux'da aniqlanadi. Paket boshqa platformalarda
// ham quriladi, lekin biriktirish baribir ishlamaydi.
func isLayer3(string) (bool, error) { return false, nil }
