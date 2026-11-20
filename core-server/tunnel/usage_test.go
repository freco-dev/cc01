package tunnel

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// waitUsage hisoblagichlar want ga yetishini kutadi. Hisoblash nusxa
// goroutine'ida yozish QAYTGANDAN keyin bo'ladi — qabul qiluvchi
// baytlarni biroz oldinroq ko'rishi mumkin.
func waitUsage(t *testing.T, tn Tunnel, want Usage) {
	t.Helper()
	deadline := time.Now().Add(ioTimeout)
	for {
		got := tn.Usage()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Usage: %+v kutilgan, %+v olindi", want, got)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// transfer src'ga payload yozadi va dst'dan aynan shuni o'qiydi.
func transfer(t *testing.T, src, dst net.Conn, payload []byte) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := src.Write(payload); err != nil {
			t.Errorf("yozish: %v", err)
		}
	}()
	_ = dst.SetReadDeadline(time.Now().Add(ioTimeout))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(dst, got); err != nil {
		t.Fatalf("o'qish: %v", err)
	}
	wg.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatal("ko'prikdan o'tgan baytlar mos emas")
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// Haqiqiy ko'prik orqali: ommaviy → xususiy baytlar BytesIn ga,
// xususiy → ommaviy baytlar BytesOut ga, aniq (Bind bufer hajmidan katta
// va unga karrali bo'lmagan hajmlar bilan).
func TestUsage_CountsBridgedTCPBytesExactly(t *testing.T) {
	tn, control := openTCP(t, 10)

	if got := tn.Usage(); got != (Usage{}) {
		t.Fatalf("yangi tunnel: %+v", got)
	}

	const in1, out1 = 100_003, 250_017
	public := dialPort(t, tn.PublicServerPort())
	received := readConnectionReceived(t, control)
	private := pair(t, tn.PrivateServerPort(), received.GetClientPort())
	transfer(t, public, private, randomBytes(t, in1))
	transfer(t, private, public, randomBytes(t, out1))
	waitUsage(t, tn, Usage{BytesIn: in1, BytesOut: out1, Connections: 1})

	// Ikkinchi ulanish: kumulyativ qiymatlar qo'shiladi.
	const in2, out2 = 7, 4096
	public2 := dialPort(t, tn.PublicServerPort())
	received2 := readConnectionReceived(t, control)
	private2 := pair(t, tn.PrivateServerPort(), received2.GetClientPort())
	transfer(t, public2, private2, randomBytes(t, in2))
	transfer(t, private2, public2, randomBytes(t, out2))
	waitUsage(t, tn, Usage{BytesIn: in1 + in2, BytesOut: out1 + out2, Connections: 2})

	// Ulanishlar yopilgandan keyin ham qiymatlar o'zgarmaydi.
	_ = public.Close()
	_ = private2.Close()
	expectClosed(t, private)
	expectClosed(t, public2)
	waitUsage(t, tn, Usage{BytesIn: in1 + in2, BytesOut: out1 + out2, Connections: 2})
}

// HTTP: Host'ni aniqlash uchun oldindan o'qilgan bufer ham BytesIn ga
// kiradi (u xususiy tomonga yetkaziladi).
func TestUsage_HTTPInitialBufferCountsAsBytesIn(t *testing.T) {
	tn, control := openHTTP(t, 10)

	head := []byte("GET / HTTP/1.1\r\nHost: http.test\r\n\r\n")
	pubSrv, pubCli := loopback(t)
	if err := tn.PublicConnectionHandler(pubSrv, head); err != nil {
		t.Fatal(err)
	}
	received := readConnectionReceived(t, control)
	private := pair(t, tn.PrivateServerPort(), received.GetClientPort())
	_ = private.SetReadDeadline(time.Now().Add(ioTimeout))
	if _, err := io.ReadFull(private, make([]byte, len(head))); err != nil {
		t.Fatal(err)
	}

	body := randomBytes(t, 5000)
	transfer(t, pubCli, private, body)
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	transfer(t, private, pubCli, response)

	waitUsage(t, tn, Usage{
		BytesIn:     uint64(len(head) + len(body)),
		BytesOut:    uint64(len(response)),
		Connections: 1,
	})
}

// max_conns tufayli rad etilgan ulanish Rejected ga, qabul qilingani
// Connections ga tushadi; rad etilgan ulanish trafigi hisoblanmaydi.
func TestUsage_RejectedAtMaxConns(t *testing.T) {
	tn, control := openTCP(t, 1)

	_ = dialPort(t, tn.PublicServerPort())
	if readConnectionReceived(t, control).GetRateLimited() {
		t.Fatal("1-ulanish limitga tushmasligi kerak")
	}
	for range 2 {
		c := dialPort(t, tn.PublicServerPort())
		if !readConnectionReceived(t, control).GetRateLimited() {
			t.Fatal("ulanish limitga tushishi kerak edi")
		}
		expectClosed(t, c)
	}
	waitUsage(t, tn, Usage{Connections: 1, Rejected: 2})

	// Tunnel ochilmasdan (yoki yopilgandan keyin) kelgan ulanish limit
	// sababli rad etilgan emas — Rejected ga kirmaydi.
	tn.Close()
	late, _ := loopback(t)
	if err := tn.acceptPublic(late, nil); err == nil {
		t.Fatal("yopilgan tunnel ulanish qabul qilmasligi kerak")
	}
	waitUsage(t, tn, Usage{Connections: 1, Rejected: 2})
}

// Close ko'prik nusxalarini kutadi: qaytgandan keyin Usage() yakuniy —
// yopilish paytida yo'lda bo'lgan baytlar ham hisoblangan, keyin hech
// narsa qo'shilmaydi (oxirgi foydalanish oynasi aniq bo'lishi uchun).
func TestUsage_FinalAfterClose(t *testing.T) {
	tn, control := openTCP(t, 10)

	public := dialPort(t, tn.PublicServerPort())
	received := readConnectionReceived(t, control)
	private := pair(t, tn.PrivateServerPort(), received.GetClientPort())

	// Ikki tomonga uzluksiz oqim; qabul qiluvchilar o'qib turadi.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, c := range []net.Conn{public, private} {
		wg.Add(2)
		go func() {
			defer wg.Done()
			chunk := make([]byte, 1500)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := c.Write(chunk); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			_, _ = io.Copy(io.Discard, c)
		}()
	}
	time.Sleep(50 * time.Millisecond)

	tn.Close()
	final := tn.Usage()
	if final.BytesIn == 0 || final.BytesOut == 0 {
		t.Fatalf("trafik hisoblanmadi: %+v", final)
	}
	close(stop)
	_ = public.Close()
	_ = private.Close()
	wg.Wait()
	time.Sleep(20 * time.Millisecond)
	if got := tn.Usage(); got != final {
		t.Fatalf("Close'dan keyin hisoblagich o'zgardi: %+v → %+v", final, got)
	}
}
