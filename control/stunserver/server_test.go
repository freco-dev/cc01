package stunserver

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	pion "github.com/pion/stun/v3"
)

func startServer(t *testing.T) *Server {
	t.Helper()

	server, err := Listen("[::1]:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	go server.Serve()
	t.Cleanup(func() { _ = server.Close() })

	return server
}

func dial(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("klient soketi: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// Serverning butun ma'nosi: so'ragan tomonga uning KO'RINGAN manzilini
// aytish.
func TestServe_ReturnsCallersAddress(t *testing.T) {
	server := startServer(t)
	client := dial(t)

	request, err := pion.Build(pion.TransactionID, pion.BindingRequest)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if _, err := client.WriteToUDPAddrPort(request.Raw, server.Addr()); err != nil {
		t.Fatalf("yuborish: %v", err)
	}

	buf := make([]byte, 1500)
	n, _, err := client.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("javob: %v", err)
	}

	response := &pion.Message{Raw: append([]byte(nil), buf[:n]...)}
	if err := response.Decode(); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if response.Type != pion.BindingSuccess {
		t.Errorf("BindingSuccess kutilgan, %v olindi", response.Type)
	}
	if response.TransactionID != request.TransactionID {
		t.Error("tranzaksiya ID mos kelmadi")
	}

	var mapped pion.XORMappedAddress
	if err := mapped.GetFrom(response); err != nil {
		t.Fatalf("XOR-MAPPED-ADDRESS: %v", err)
	}

	local := client.LocalAddr().(*net.UDPAddr).AddrPort()
	if mapped.Port != int(local.Port()) {
		t.Errorf("port %d kutilgan, %d olindi", local.Port(), mapped.Port)
	}
}

// Har bir so'rov mustaqil — server holatsiz bo'lishi kerak.
func TestServe_HandlesRepeatedRequests(t *testing.T) {
	server := startServer(t)
	client := dial(t)

	buf := make([]byte, 1500)

	for i := range 5 {
		request, err := pion.Build(pion.TransactionID, pion.BindingRequest)
		if err != nil {
			t.Fatalf("Build %d: %v", i, err)
		}

		if _, err := client.WriteToUDPAddrPort(request.Raw, server.Addr()); err != nil {
			t.Fatalf("yuborish %d: %v", i, err)
		}

		n, _, err := client.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("javob %d: %v", i, err)
		}

		response := &pion.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := response.Decode(); err != nil {
			t.Fatalf("Decode %d: %v", i, err)
		}
		if response.TransactionID != request.TransactionID {
			t.Errorf("%d: tranzaksiya ID mos kelmadi", i)
		}
	}
}

// STUN bo'lmagan paketlar serverni yiqitmasligi kerak: port skanerlash
// va tasodifiy shovqin odatiy hol.
func TestServe_IgnoresNonStunTraffic(t *testing.T) {
	server := startServer(t)
	client := dial(t)

	for _, junk := range [][]byte{
		[]byte("salom"),
		make([]byte, 1),
		make([]byte, 200),
	} {
		if _, err := client.WriteToUDPAddrPort(junk, server.Addr()); err != nil {
			t.Fatalf("yuborish: %v", err)
		}
	}

	// Server hali javob berayotgan bo'lishi kerak.
	request, _ := pion.Build(pion.TransactionID, pion.BindingRequest)
	if _, err := client.WriteToUDPAddrPort(request.Raw, server.Addr()); err != nil {
		t.Fatalf("yuborish: %v", err)
	}

	buf := make([]byte, 1500)
	if _, _, err := client.ReadFromUDPAddrPort(buf); err != nil {
		t.Fatalf("axlatdan keyin javob kelmadi: %v", err)
	}
}

func TestClose_IsIdempotent(t *testing.T) {
	server, err := Listen("[::1]:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go server.Serve()

	if err := server.Close(); err != nil {
		t.Fatalf("birinchi Close: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Errorf("ikkinchi Close: %v", err)
	}
}

func TestListen_RejectsBadAddress(t *testing.T) {
	if _, err := Listen("axlat", nil); err == nil {
		t.Fatal("yaroqsiz manzil rad etilishi kerak edi")
	}
}

func TestAddr_IsValid(t *testing.T) {
	server := startServer(t)

	addr := server.Addr()
	if !addr.IsValid() || addr.Port() == 0 {
		t.Errorf("manzil yaroqsiz: %v", addr)
	}
	_ = netip.AddrPort(addr)
}
