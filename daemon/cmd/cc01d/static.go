package main

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/freco-dev/cc01/daemon/engine"
	"github.com/freco-dev/cc01/daemon/session"
)

// staticBackend — statik rejim uchun IPC backend'i.
//
// Statik rejimda mesh demon bilan bir umr ko'radi: peerlar bayroqlardan
// keladi, ya'ni ularni qayta o'qish uchun demonni qayta ishga tushirish
// kerak. Shuning uchun `up`/`down` bu yerda ma'noga ega emas — lekin
// `status`, `peer list` va `doctor` aynan shu qadar foydali.
type staticBackend struct {
	engine  *engine.Engine
	address netip.Prefix
	started time.Time
}

// errStaticMode — statik rejimda qo'llab-quvvatlanmaydigan amal.
var errStaticMode = errors.New(
	"statik rejimda qo'llab-quvvatlanmaydi; mesh demon bilan birga ko'tariladi va tushadi")

func (b *staticBackend) Status() (session.Status, bool) {
	// Endpoints bo'sh: statik rejimda hech kimga hech narsa e'lon
	// qilinmaydi — peer bizning manzilimizni o'z bayrog'idan biladi.
	return session.Status{
		PublicKey:  b.engine.PublicKey(),
		Address:    b.address.String(),
		Interface:  b.engine.InterfaceName(),
		ListenPort: b.engine.ListenPort(),
		Since:      b.started,
	}, true
}

func (b *staticBackend) Peers() []engine.PeerSnapshot { return b.engine.Snapshot() }

func (b *staticBackend) Up(context.Context) error { return errStaticMode }
func (b *staticBackend) Down() error              { return errStaticMode }
