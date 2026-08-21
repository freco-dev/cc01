package noise

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// Faza 1 qabul mezoni: "ikki daemon kalit almashadi, shifrlangan echo
// ishlaydi". Bu test haqiqiy UDP soketlari orqali to'liq oqimni
// tekshiradi — handshake, ikki tomonlama shifrlangan almashinuv va
// yopilish.
//
// Ikkala tomon bitta jarayonda, lekin alohida soketlarda va alohida
// goroutine'larda: yadro tarmoq stegi haqiqatan ishtirok etadi.
func TestNoiseOverUDP_HandshakeAndEcho(t *testing.T) {
	alice, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	bobConn := listenUDP(t)
	aliceConn := listenUDP(t)
	bobAddr := bobConn.LocalAddr().(*net.UDPAddr)

	const message = "cc01 mesh: UDP orqali shifrlangan echo"

	var wg sync.WaitGroup
	wg.Add(1)

	// ── Responder (Bob) ────────────────────────────────────────
	go func() {
		defer wg.Done()

		handshake, err := StartResponder(bob)
		if err != nil {
			t.Errorf("bob StartResponder: %v", err)
			return
		}

		buf := make([]byte, 2048)
		n, peer, err := bobConn.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("bob initiation o'qish: %v", err)
			return
		}

		if err := handshake.ReadInitiation(buf[:n]); err != nil {
			t.Errorf("bob ReadInitiation: %v", err)
			return
		}

		// IK: initiatorning kim ekani endi ma'lum.
		if handshake.PeerStatic() != alice.PublicKey() {
			t.Errorf("bob peer: %s kutilgan, %s olindi",
				alice.PublicKey(), handshake.PeerStatic())
		}

		response, session, err := handshake.WriteResponse()
		if err != nil {
			t.Errorf("bob WriteResponse: %v", err)
			return
		}
		if _, err := bobConn.WriteToUDP(response, peer); err != nil {
			t.Errorf("bob javob yuborish: %v", err)
			return
		}

		// Echo: kelgan har bir paketni ochib, qaytarib shifrlaymiz.
		n, _, err = bobConn.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("bob data o'qish: %v", err)
			return
		}

		header, plaintext, err := session.Open(buf[:n])
		if err != nil {
			t.Errorf("bob Open: %v", err)
			return
		}
		if header.Type != TypeData {
			t.Errorf("bob: tur %s olindi", header.Type)
		}
		if string(plaintext) != message {
			t.Errorf("bob: %q kutilgan, %q olindi", message, plaintext)
		}

		echo, err := session.Seal(TypeData, plaintext)
		if err != nil {
			t.Errorf("bob Seal: %v", err)
			return
		}
		if _, err := bobConn.WriteToUDP(echo, peer); err != nil {
			t.Errorf("bob echo yuborish: %v", err)
		}
	}()

	// ── Initiator (Alice) ──────────────────────────────────────
	handshake, err := StartInitiator(alice, bob.PublicKey())
	if err != nil {
		t.Fatalf("alice StartInitiator: %v", err)
	}

	initiation, err := handshake.WriteInitiation()
	if err != nil {
		t.Fatalf("alice WriteInitiation: %v", err)
	}
	if _, err := aliceConn.WriteToUDP(initiation, bobAddr); err != nil {
		t.Fatalf("alice initiation yuborish: %v", err)
	}

	buf := make([]byte, 2048)
	n, _, err := aliceConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("alice javob o'qish: %v", err)
	}

	session, err := handshake.ReadResponse(buf[:n])
	if err != nil {
		t.Fatalf("alice ReadResponse: %v", err)
	}
	if session.Peer() != bob.PublicKey() {
		t.Errorf("alice peer: %s kutilgan, %s olindi", bob.PublicKey(), session.Peer())
	}

	packet, err := session.Seal(TypeData, []byte(message))
	if err != nil {
		t.Fatalf("alice Seal: %v", err)
	}
	if bytes.Contains(packet, []byte(message)) {
		t.Fatal("ochiq matn simda ko'rinib turibdi")
	}
	if _, err := aliceConn.WriteToUDP(packet, bobAddr); err != nil {
		t.Fatalf("alice data yuborish: %v", err)
	}

	n, _, err = aliceConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("alice echo o'qish: %v", err)
	}

	_, echoed, err := session.Open(buf[:n])
	if err != nil {
		t.Fatalf("alice echo Open: %v", err)
	}
	if string(echoed) != message {
		t.Errorf("echo: %q kutilgan, %q olindi", message, echoed)
	}

	wg.Wait()
}

// Simda ushlab qolingan paketni qayta yuborish — eng oddiy hujum.
// UDP orqali ham replay oynasi ushlab qolishi kerak.
func TestNoiseOverUDP_ReplayIsRejected(t *testing.T) {
	alice, _ := GenerateIdentity()
	bob, _ := GenerateIdentity()

	bobConn := listenUDP(t)
	aliceConn := listenUDP(t)
	bobAddr := bobConn.LocalAddr().(*net.UDPAddr)

	type result struct {
		firstErr, secondErr error
	}
	results := make(chan result, 1)

	go func() {
		handshake, _ := StartResponder(bob)

		buf := make([]byte, 2048)
		n, peer, err := bobConn.ReadFromUDP(buf)
		if err != nil {
			results <- result{firstErr: err}
			return
		}
		if err := handshake.ReadInitiation(buf[:n]); err != nil {
			results <- result{firstErr: err}
			return
		}

		response, session, err := handshake.WriteResponse()
		if err != nil {
			results <- result{firstErr: err}
			return
		}
		_, _ = bobConn.WriteToUDP(response, peer)

		n, _, _ = bobConn.ReadFromUDP(buf)
		_, _, first := session.Open(bytes.Clone(buf[:n]))

		n, _, _ = bobConn.ReadFromUDP(buf)
		_, _, second := session.Open(buf[:n])

		results <- result{firstErr: first, secondErr: second}
	}()

	handshake, _ := StartInitiator(alice, bob.PublicKey())
	initiation, _ := handshake.WriteInitiation()
	_, _ = aliceConn.WriteToUDP(initiation, bobAddr)

	buf := make([]byte, 2048)
	n, _, err := aliceConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("javob o'qish: %v", err)
	}
	session, err := handshake.ReadResponse(buf[:n])
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	packet, _ := session.Seal(TypeData, []byte("bir marta"))

	// Aynan bir xil paketni ikki marta yuboramiz.
	_, _ = aliceConn.WriteToUDP(packet, bobAddr)
	_, _ = aliceConn.WriteToUDP(packet, bobAddr)

	select {
	case got := <-results:
		if got.firstErr != nil {
			t.Fatalf("birinchi paket rad etildi: %v", got.firstErr)
		}
		if !errors.Is(got.secondErr, ErrReplay) {
			t.Fatalf("takroriy paket uchun ErrReplay kutilgan, olindi: %v", got.secondErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("responder javob bermadi")
	}
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("UDP soket ochish: %v", err)
	}

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
