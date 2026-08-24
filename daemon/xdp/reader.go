package xdp

import "bytes"

// newReader ichkariga joylashtirilgan ELF ni o'qish uchun.
func newReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }
