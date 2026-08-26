package control

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/freco-dev/cc01/daemon/noise"
)

// nodeIDFor public kalitdan node_id hisoblaydi.
//
// Formula CP dagi bilan bir xil bo'lishi SHART
// (ARCHITECTURE.md §3.1.2: node_id = SHA-256(pubkey)).
func nodeIDFor(key noise.PublicKey) string {
	sum := sha256.Sum256(key[:])
	return hex.EncodeToString(sum[:])
}
