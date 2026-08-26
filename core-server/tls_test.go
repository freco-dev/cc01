package main

import (
	"testing"

	"github.com/freco-dev/cc01/core-server/tlsmgr"
)

// ⚠️ Go'da nil ko'rsatkichni interfeysga solganda natija nil
// BO'LMAYDI. `Options.Issuer` ga to'g'ridan-to'g'ri `*ACME` nil
// bersak, resolver "chiqaruvchi bor" deb hisoblab, nil
// ko'rsatkich orqali metod chaqirardi.
func TestIssuerOrNil_ReturnsTrueNil(t *testing.T) {
	if got := issuerOrNil(nil); got != nil {
		t.Errorf("nil *ACME → %#v, nil kutilgan edi", got)
	}
}

func TestIssuerOrNil_PassesRealIssuer(t *testing.T) {
	acme, err := tlsmgr.NewACME(tlsmgr.ACMEOptions{
		Email:     "admin@cc01.uz",
		Directory: t.TempDir(),
		CA:        tlsmgr.LetsEncryptStaging,
		Decide:    func(string) bool { return true },
	})
	if err != nil {
		t.Fatalf("NewACME: %v", err)
	}

	if got := issuerOrNil(acme); got == nil {
		t.Error("haqiqiy chiqaruvchi yo'qoldi")
	}
}
