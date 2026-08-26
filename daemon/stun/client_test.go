package stun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	pion "github.com/pion/stun/v3"
)

// testServer — minimal STUN serveri: binding request'ga so'ragan
// tomonning manzili bilan javob beradi.
type testServer struct {
	conn     *net.UDPConn
	addr     netip.AddrPort
	requests atomic.Int32

	// silent — javob bermaslik (taymaut sinovi uchun).
	silent atomic.Bool
}

func startServer(t *testing.T) *testServer {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("server soketi: %v", err)
	}

	server := &testServer{
		conn: conn,
		addr: conn.LocalAddr().(*net.UDPAddr).AddrPort(),
	}

	go server.serve()
	t.Cleanup(func() { _ = conn.Close() })

	return server
}

func (s *testServer) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		s.requests.Add(1)

		if s.silent.Load() {
			continue
		}

		request := &pion.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := request.Decode(); err != nil {
			continue
		}

		response, err := pion.Build(
			request,
			pion.BindingSuccess,
			&pion.XORMappedAddress{
				IP:   net.IP(from.Addr().AsSlice()),
				Port: int(from.Port()),
			},
		)
		if err != nil {
			continue
		}

		_, _ = s.conn.WriteToUDPAddrPort(response.Raw, from)
	}
}

// newClientWithSocket klientni haqiqiy soket bilan ulaydi va kelgan
// paketlarni unga uzatadi — engine aynan shunday qiladi.
func newClientWithSocket(t *testing.T) (*Client, netip.AddrPort) {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("klient soketi: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client := New(func(payload []byte, to netip.AddrPort) error {
		_, err := conn.WriteToUDPAddrPort(payload, to)
		return err
	})

	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			client.Handle(buf[:n])
		}
	}()

	return client, conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestDiscover_ReturnsMappedAddress(t *testing.T) {
	server := startServer(t)
	client, local := newClientWithSocket(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	mapped, err := client.Discover(ctx, server.addr)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// Loopbackda NAT yo'q, ya'ni ko'rilgan port bizniki bilan bir xil
	// bo'lishi kerak. Bu aynan STUN'ning ma'nosini tekshiradi:
	// server BIZ FOYDALANGAN soketning manzilini qaytaradi.
	if mapped.Port() != local.Port() {
		t.Errorf("port %d kutilgan, %d olindi", local.Port(), mapped.Port())
	}
	if !mapped.Addr().IsLoopback() {
		t.Errorf("loopback manzil kutilgan, %v olindi", mapped.Addr())
	}
}

func TestDiscover_TimesOutWhenServerSilent(t *testing.T) {
	server := startServer(t)
	server.silent.Store(true)

	client, _ := newClientWithSocket(t)

	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()

	_, err := client.Discover(ctx, server.addr)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("ErrTimeout kutilgan, olindi: %v", err)
	}

	// Qayta urinishlar bo'lgan bo'lishi kerak: UDP ishonchsiz.
	if got := server.requests.Load(); got < 2 {
		t.Errorf("kamida 2 urinish kutilgan, %d bo'ldi", got)
	}
}

func TestDiscover_RejectsInvalidServer(t *testing.T) {
	client, _ := newClientWithSocket(t)

	if _, err := client.Discover(t.Context(), netip.AddrPort{}); err == nil {
		t.Fatal("yaroqsiz manzil rad etilishi kerak edi")
	}
}

func TestDiscover_CancelledContext(t *testing.T) {
	server := startServer(t)
	server.silent.Store(true)

	client, _ := newClientWithSocket(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := client.Discover(ctx, server.addr); !errors.Is(err, context.Canceled) {
		t.Fatalf("context.Canceled kutilgan, olindi: %v", err)
	}
}

// ═══════════════ Paketlarni ajratish ═══════════════

// cc01 paketlari STUN deb qabul qilinmasligi kerak — bu butun
// datapath'ni buzardi.
func TestIsMessage_RejectsCc01Packets(t *testing.T) {
	// noise.HeaderSize = 16; birinchi bayt — tur (0x01..0x06).
	for packetType := byte(1); packetType <= 6; packetType++ {
		packet := make([]byte, 64)
		packet[0] = packetType

		// receiver_index ni turli qiymatlar bilan sinaymiz.
		for _, index := range []byte{0x00, 0x11, 0xff, 0x21} {
			packet[4], packet[5], packet[6], packet[7] = index, index, index, index

			if IsMessage(packet) {
				t.Errorf("cc01 paketi (tur=%d, index=%#x) STUN deb qabul qilindi",
					packetType, index)
			}
		}
	}
}

func TestIsMessage_AcceptsRealStunMessage(t *testing.T) {
	message, err := pion.Build(pion.TransactionID, pion.BindingRequest)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if !IsMessage(message.Raw) {
		t.Error("haqiqiy STUN xabari tanilmadi")
	}
}

func TestIsMessage_RejectsGarbage(t *testing.T) {
	for _, payload := range [][]byte{
		nil,
		{},
		{0x00},
		make([]byte, 19), // STUN sarlavhasi 20 bayt
	} {
		if IsMessage(payload) {
			t.Errorf("axlat STUN deb qabul qilindi: %x", payload)
		}
	}
}

// Boshqa birov yuborgan STUN javobi qabul qilinmasligi kerak —
// tranzaksiya ID'si mos kelmaydi.
func TestHandle_IgnoresUnknownTransaction(t *testing.T) {
	client := New(func([]byte, netip.AddrPort) error { return nil })

	response, err := pion.Build(
		pion.TransactionID,
		pion.BindingSuccess,
		&pion.XORMappedAddress{IP: net.ParseIP("203.0.113.7"), Port: 41022},
	)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// STUN xabari — shuning uchun `true`, lekin hech kim kutmagan.
	if !client.Handle(response.Raw) {
		t.Error("STUN xabari deb tanilishi kerak edi")
	}
	if client.Pending() != 0 {
		t.Errorf("kutayotgan so'rov qolmasligi kerak: %d", client.Pending())
	}
}

func TestHandle_ReturnsFalseForNonStun(t *testing.T) {
	client := New(func([]byte, netip.AddrPort) error { return nil })

	packet := make([]byte, 32)
	packet[0] = 0x04 // noise.TypeData

	if client.Handle(packet) {
		t.Error("cc01 paketi STUN sifatida yutib yuborildi")
	}
}

// So'rov tugagach kutayotganlar ro'yxati tozalanishi kerak, aks holda
// u vaqt o'tishi bilan o'sib borardi.
func TestDiscover_CleansUpPendingRequests(t *testing.T) {
	server := startServer(t)
	client, _ := newClientWithSocket(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	if _, err := client.Discover(ctx, server.addr); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if client.Pending() != 0 {
		t.Errorf("kutayotgan so'rovlar tozalanmadi: %d", client.Pending())
	}
}

// ═══════════════════════════════════════════════════════════════
// Regressiya: STUN aniqlash tugagach hech qanday o'quvchi qolmasligi
// kerak.
//
// Avvalgi versiya alohida goroutine'da o'qirdi va u `Receive` da
// bloklangan holda qolib ketardi. Keyinchalik u datapath'ning birinchi
// paketini — handshake initiation'ni — o'g'irlab, mesh'ni jimgina
// ishlamaydigan qilib qo'yardi.
// ═══════════════════════════════════════════════════════════════
func TestDiscoverOnce_LeavesNoReaderBehind(t *testing.T) {
	server := startServer(t)

	socket := newTestSocket(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	if _, err := DiscoverOnce(ctx, socket, server.addr); err != nil {
		t.Fatalf("DiscoverOnce: %v", err)
	}

	// Endi begona "paket" yuboramiz. Uni FAQAT biz o'qiy olishimiz
	// kerak — qolib ketgan goroutine bo'lsa, u o'g'irlab ketadi.
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("yuboruvchi: %v", err)
	}
	defer sender.Close()

	marker := []byte("datapath-paketi")
	if _, err := sender.WriteToUDPAddrPort(marker, socket.addr); err != nil {
		t.Fatalf("yuborish: %v", err)
	}

	buf := make([]byte, 1500)
	n, _, err := socket.ReceiveOne(buf, time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatalf("paket o'g'irlandi yoki yetib kelmadi: %v", err)
	}
	if string(buf[:n]) != string(marker) {
		t.Errorf("%q kutilgan, %q olindi", marker, buf[:n])
	}
}

// testSocket — stun.Socket interfeysining minimal implementatsiyasi.
type testSocket struct {
	conn *net.UDPConn
	addr netip.AddrPort
}

func newTestSocket(t *testing.T) *testSocket {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatalf("soket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return &testSocket{conn: conn, addr: conn.LocalAddr().(*net.UDPAddr).AddrPort()}
}

func (s *testSocket) Send(payload []byte, to netip.AddrPort) error {
	_, err := s.conn.WriteToUDPAddrPort(payload, to)
	return err
}

func (s *testSocket) ReceiveOne(buf []byte, deadline time.Time) (int, netip.AddrPort, error) {
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return 0, netip.AddrPort{}, err
	}
	defer func() { _ = s.conn.SetReadDeadline(time.Time{}) }()

	return s.conn.ReadFromUDPAddrPort(buf)
}
