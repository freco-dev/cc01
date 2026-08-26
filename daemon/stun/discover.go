package stun

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"time"
)

// Socket — mustaqil STUN almashinuvi uchun kerakli minimal soket.
//
// `conn.Bind` uni qanoatlantiradi.
type Socket interface {
	Send(payload []byte, to netip.AddrPort) error
	ReceiveOne(buf []byte, deadline time.Time) (int, netip.AddrPort, error)
}

// DiscoverOnce public manzilni SINXRON aniqlaydi: qaytgan paytda
// hech qanday goroutine qolmaydi.
//
// Bu muhim. Agar o'qish alohida goroutine'da bo'lsa, u `Receive` da
// bloklangan holda qolib ketadi va keyinchalik datapath'ning
// paketlarini o'g'irlaydi — handshake jimgina ishlamay qo'yadi.
// Shuning uchun bu funksiya o'qishni CHAQIRUVCHI goroutine'da bajaradi.
//
// Engine ishga tushgandan keyin bu funksiya ishlatilmaydi: u yerda
// javoblarni engine demultiplekslab, `Client.Handle` ga uzatadi.
func DiscoverOnce(
	ctx context.Context,
	socket Socket,
	server netip.AddrPort,
) (netip.AddrPort, error) {
	client := New(socket.Send)

	type outcome struct {
		addr netip.AddrPort
		err  error
	}
	done := make(chan outcome, 1)

	go func() {
		addr, err := client.Discover(ctx, server)
		done <- outcome{addr, err}
	}()

	buf := make([]byte, 1500)

	for {
		select {
		case result := <-done:
			return result.addr, result.err
		default:
		}

		// Qisqa deadline: Discover tugaganini tez-tez tekshirib
		// turishimiz kerak.
		n, _, err := socket.ReceiveOne(buf, time.Now().Add(200*time.Millisecond))
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			// Soket yopilgan yoki boshqa jiddiy xato — Discover
			// baribir taymaut bilan tugaydi, uni kutamiz.
			result := <-done
			return result.addr, result.err
		}

		client.Handle(buf[:n])
	}
}
