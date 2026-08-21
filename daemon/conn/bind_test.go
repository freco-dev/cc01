package conn

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func openBind(t *testing.T) *Bind {
	t.Helper()

	bind, err := Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = bind.Close() })
	return bind
}

func TestOpen_AssignsPort(t *testing.T) {
	bind := openBind(t)

	if bind.Port() == 0 {
		t.Error("yadro port ajratishi kerak edi")
	}
	if !bind.LocalAddr().IsValid() {
		t.Error("lokal manzil yaroqsiz")
	}
}

func TestOpen_SpecificPort(t *testing.T) {
	// Bo'sh port topamiz, yopamiz, keyin o'shani so'raymiz.
	probe, err := Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	port := probe.Port()
	_ = probe.Close()

	bind, err := Open(port)
	if err != nil {
		t.Skipf("port %d band bo'lib qoldi: %v", port, err)
	}
	defer bind.Close()

	if bind.Port() != port {
		t.Errorf("port %d kutilgan, %d olindi", port, bind.Port())
	}
}

func TestSendReceive_RoundTrip(t *testing.T) {
	receiver := openBind(t)
	sender := openBind(t)

	target := netip.AddrPortFrom(netip.IPv6Loopback(), receiver.Port())
	payload := []byte("cc01 datagram")

	if err := sender.Send(payload, target); err != nil {
		t.Fatalf("Send: %v", err)
	}

	messages := NewDatagrams(4, 2048)
	count, err := receiveWithTimeout(t, receiver, messages)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if count != 1 {
		t.Fatalf("1 paket kutilgan, %d olindi", count)
	}
	if string(messages[0].Payload) != string(payload) {
		t.Errorf("%q kutilgan, %q olindi", payload, messages[0].Payload)
	}

	// Manba porti javob yuborish uchun kerak.
	if messages[0].From.Port() != sender.Port() {
		t.Errorf("manba porti %d kutilgan, %d olindi", sender.Port(), messages[0].From.Port())
	}
}

// Batch qabul qilish bir nechta paketni bitta chaqiruvda olishi kerak —
// bu Linux'da recvmmsg'ga tushadi.
func TestReceive_MultiplePackets(t *testing.T) {
	receiver := openBind(t)
	sender := openBind(t)

	target := netip.AddrPortFrom(netip.IPv6Loopback(), receiver.Port())

	const total = 8
	for i := range total {
		if err := sender.Send([]byte{byte(i)}, target); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	seen := make(map[byte]bool, total)
	messages := NewDatagrams(BatchSize, 2048)

	for len(seen) < total {
		count, err := receiveWithTimeout(t, receiver, messages)
		if err != nil {
			t.Fatalf("Receive (%d/%d olindi): %v", len(seen), total, err)
		}
		for i := range count {
			seen[messages[i].Payload[0]] = true
		}
		// Buferlar Receive'da qisqartirilgan — qayta tiklaymiz.
		messages = NewDatagrams(BatchSize, 2048)
	}

	if len(seen) != total {
		t.Errorf("%d paket kutilgan, %d olindi", total, len(seen))
	}
}

func TestSend_RejectsInvalidEndpoint(t *testing.T) {
	bind := openBind(t)

	if err := bind.Send([]byte("x"), netip.AddrPort{}); err == nil {
		t.Fatal("yaroqsiz endpoint rad etilishi kerak edi")
	}
}

// Yopilgan soketdagi bloklangan Receive tushunarli xato qaytarishi kerak,
// "use of closed network connection" emas.
func TestClose_UnblocksReceive(t *testing.T) {
	bind, err := Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		messages := NewDatagrams(4, 2048)
		_, err := bind.Receive(messages)
		result <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := bind.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-result:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("ErrClosed kutilgan, olindi: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Receive blokda qoldi")
	}
}

func TestClose_IsIdempotent(t *testing.T) {
	bind, err := Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := bind.Close(); err != nil {
		t.Fatalf("birinchi Close: %v", err)
	}
	if err := bind.Close(); err != nil {
		t.Errorf("ikkinchi Close xato qaytardi: %v", err)
	}
}

func receiveWithTimeout(t *testing.T, bind *Bind, messages []Datagram) (int, error) {
	t.Helper()

	if err := bind.socket.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
	defer bind.socket.SetReadDeadline(time.Time{})

	return bind.Receive(messages)
}
