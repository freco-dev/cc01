package session

import (
	"context"
	"net/netip"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
	"github.com/freco-dev/cc01/daemon/stun"
)

// discoverPublic overlay soketining public manzilini aniqlaydi.
//
// So'rov AYNAN o'sha soketdan yuboriladi — NAT bog'lanishi soketga
// bog'langan, boshqa soketdan so'ralgan manzil overlay uchun yaroqsiz
// bo'lardi.
//
// Bu engine ishga tushishidan OLDIN chaqiriladi, shuning uchun
// `DiscoverOnce` ishlatiladi: u qaytgan paytda hech qanday o'quvchi
// goroutine qolmaydi. Aks holda o'sha goroutine keyinchalik datapath
// paketlarini o'g'irlab, handshake'ni jimgina buzardi.
func discoverPublic(bind *conn.Bind, server netip.AddrPort) (netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return stun.DiscoverOnce(ctx, bind, server)
}
