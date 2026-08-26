// Package conn overlay uchun UDP transportini beradi.
//
// Batch I/O `golang.org/x/net/ipv6` orqali: Linux'da u `recvmmsg`/
// `sendmmsg` ga tushadi, ya'ni bitta syscall'da bir nechta paket
// o'tkaziladi (DEV_SPEC §3.2). Boshqa platformalarda kutubxona o'zi
// bittalab rejimga qaytadi — chaqiruvchi uchun API bir xil qoladi.
package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/ipv6"
)

// DefaultPort — overlay uchun standart UDP porti (ARCHITECTURE.md §3.2.2).
const DefaultPort = 51820

// BatchSize — bitta syscall'da o'tkaziladigan paketlar soni.
const BatchSize = 128

// ErrClosed — soket yopilgan.
var ErrClosed = errors.New("conn: soket yopilgan")

// Bind — overlay UDP soketi.
//
// Bitta soket ham IPv4, ham IPv6 endpointlar bilan ishlaydi: u
// dual-stack rejimda ochiladi, IPv4 peerlar `::ffff:a.b.c.d` ko'rinishida
// ko'rinadi. Bu kerak, chunki overlay IPv6 bo'lsa ham, UNDERLAY tarmoq
// ko'pincha IPv4.
type Bind struct {
	socket *net.UDPConn
	packet *ipv6.PacketConn
	port   uint16

	closeOnce sync.Once
	closed    chan struct{}
}

// Open berilgan portda soket ochadi. Port 0 bo'lsa yadro tanlaydi.
func Open(port uint16) (*Bind, error) {
	socket, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, fmt.Errorf("conn: UDP soket ochish (:%d): %w", port, err)
	}

	local, ok := socket.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = socket.Close()
		return nil, errors.New("conn: kutilmagan lokal manzil turi")
	}

	return &Bind{
		socket: socket,
		packet: ipv6.NewPacketConn(socket),
		port:   uint16(local.Port),
		closed: make(chan struct{}),
	}, nil
}

// Port — soket eshitayotgan port.
func (b *Bind) Port() uint16 { return b.port }

// LocalAddr — soketning lokal manzili.
func (b *Bind) LocalAddr() netip.AddrPort {
	local, ok := b.socket.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	return local.AddrPort()
}

// Datagram — bitta qabul qilingan paket.
type Datagram struct {
	Payload []byte
	From    netip.AddrPort
}

// Receive bir yoki bir nechta paketni o'qiydi va `messages` ni to'ldiradi.
//
// `messages` uzunligi kutilayotgan maksimal paketlar sonini belgilaydi;
// har bir `Payload` yetarli sig'imga ega bo'lishi kerak.
func (b *Bind) Receive(messages []Datagram) (int, error) {
	batch := make([]ipv6.Message, len(messages))
	for i := range batch {
		batch[i].Buffers = [][]byte{messages[i].Payload}
	}

	count, err := b.packet.ReadBatch(batch, 0)
	if err != nil {
		if b.isClosed() {
			return 0, ErrClosed
		}
		return 0, err
	}

	for i := range count {
		messages[i].Payload = messages[i].Payload[:batch[i].N]

		if addr, ok := batch[i].Addr.(*net.UDPAddr); ok {
			messages[i].From = normalize(addr.AddrPort())
		}
	}

	return count, nil
}

// ReceiveOne bitta paketni deadline bilan o'qiydi.
//
// Batch o'qishdan farqi — u qaytishi KAFOLATLANGAN. Bu engine ishga
// tushishidan oldingi qisqa almashinuvlar uchun kerak (masalan STUN):
// o'sha paytda bloklanib qoladigan o'quvchi goroutine qoldirib
// bo'lmaydi — u keyinchalik engine'ning paketlarini o'g'irlaydi.
func (b *Bind) ReceiveOne(buf []byte, deadline time.Time) (int, netip.AddrPort, error) {
	if err := b.socket.SetReadDeadline(deadline); err != nil {
		return 0, netip.AddrPort{}, err
	}
	defer func() { _ = b.socket.SetReadDeadline(time.Time{}) }()

	n, from, err := b.socket.ReadFromUDPAddrPort(buf)
	if err != nil {
		if b.isClosed() {
			return 0, netip.AddrPort{}, ErrClosed
		}
		return 0, netip.AddrPort{}, err
	}

	return n, normalize(from), nil
}

// normalize manzilni YAGONA ko'rinishga keltiradi.
//
// Dual-stack soket IPv4 peerni `::ffff:a.b.c.d` ko'rinishida qaytaradi,
// konfiguratsiyadan kelgan manzil esa sof `a.b.c.d` bo'ladi. Ular
// netip.AddrPort sifatida TENG EMAS — va bu jimgina buzilishga olib
// keladi: paket keladi, lekin "kutilgan manzildan emas" deb tashlanadi.
//
// Shuning uchun soketdan chiqadigan har bir manzil shu yerda
// normallashtiriladi.
func normalize(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

// Send paketni berilgan endpointga yuboradi.
func (b *Bind) Send(payload []byte, to netip.AddrPort) error {
	if !to.IsValid() {
		return fmt.Errorf("conn: endpoint yaroqsiz: %v", to)
	}

	_, err := b.socket.WriteToUDPAddrPort(payload, to)
	if err != nil && b.isClosed() {
		return ErrClosed
	}
	return err
}

// SendBatch bir nechta paketni bitta syscall'da yuborishga harakat qiladi.
func (b *Bind) SendBatch(messages []Datagram) (int, error) {
	if len(messages) == 0 {
		return 0, nil
	}

	batch := make([]ipv6.Message, len(messages))
	for i := range batch {
		batch[i].Buffers = [][]byte{messages[i].Payload}
		batch[i].Addr = net.UDPAddrFromAddrPort(messages[i].From)
	}

	count, err := b.packet.WriteBatch(batch, 0)
	if err != nil && b.isClosed() {
		return count, ErrClosed
	}
	return count, err
}

// Close soketni yopadi. Bloklangan Receive chaqiruvlari ErrClosed
// qaytaradi.
func (b *Bind) Close() error {
	var err error
	b.closeOnce.Do(func() {
		close(b.closed)
		err = b.socket.Close()
	})
	return err
}

func (b *Bind) isClosed() bool {
	select {
	case <-b.closed:
		return true
	default:
		return false
	}
}

// NewDatagrams qabul qilish uchun buferlar tayyorlaydi.
func NewDatagrams(size, capacity int) []Datagram {
	messages := make([]Datagram, size)
	for i := range messages {
		messages[i].Payload = make([]byte, capacity)
	}
	return messages
}
