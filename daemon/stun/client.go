// Package stun overlay soketining public manzilini aniqlaydi
// (RFC 5389, ARCHITECTURE.md §3.1.4).
//
// ⚠️ Eng muhim jihat: STUN so'rovi datapath bilan AYNAN BIR XIL UDP
// soketidan yuborilishi shart. NAT bog'lanishi (manzil:port) har bir
// soket uchun alohida yaratiladi — boshqa soketdan so'ralsa, topilgan
// manzil overlay trafigi uchun yaroqsiz bo'ladi.
//
// Shu sababli bu paket o'z soketini ochmaydi: u yuborish funksiyasini
// oladi, javoblarni esa engine unga uzatadi.
package stun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	pion "github.com/pion/stun/v3"
)

// MagicCookie — RFC 5389 dagi doimiy qiymat. Har bir STUN xabarining
// 4–8 baytlarida turadi va uni boshqa protokollardan ajratishga xizmat
// qiladi.
const MagicCookie uint32 = 0x2112A442

// transactionID — STUN so'rovini javobi bilan bog'lovchi 96-bitli
// identifikator.
type transactionID = [pion.TransactionIDSize]byte

var (
	// ErrTimeout — server javob bermadi.
	ErrTimeout = errors.New("stun: server javob bermadi")

	// ErrNoAddress — javobda XOR-MAPPED-ADDRESS yo'q.
	ErrNoAddress = errors.New("stun: javobda manzil yo'q")
)

// SendFunc paketni berilgan manzilga yuboradi. Engine o'zining UDP
// soketini shu ko'rinishda beradi.
type SendFunc func(payload []byte, to netip.AddrPort) error

// Client — STUN so'rovlarini yuboruvchi va javoblarni tranzaksiya ID'si
// bo'yicha moslashtiruvchi.
type Client struct {
	send SendFunc

	mu      sync.Mutex
	pending map[transactionID]chan netip.AddrPort
}

func New(send SendFunc) *Client {
	return &Client{
		send:    send,
		pending: make(map[transactionID]chan netip.AddrPort),
	}
}

// IsMessage — paket STUN xabarimi.
//
// Tekshiruv magic cookie ustida: cc01 paketlarining 4–8 baytlarida
// sessiya indeksi turadi, va u ataylab shu qiymatga teng bo'lmasligi
// ta'minlangan (noise paketiga qarang). Ya'ni ajratish ehtimolli emas,
// aniq.
func IsMessage(payload []byte) bool {
	return pion.IsMessage(payload)
}

// Discover berilgan STUN serveridan public manzilni so'raydi.
//
// Bir necha marta qayta uriniladi: UDP ishonchsiz va birinchi paket
// NAT jadvalini ochish uchun ketishi mumkin.
func (c *Client) Discover(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
	if !server.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("stun: server manzili yaroqsiz: %v", server)
	}

	// RFC 5389 tavsiyasiga yaqin: 500 ms dan boshlab ikkilantiramiz.
	delays := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}

	var lastErr error
	for _, timeout := range delays {
		addr, err := c.attempt(ctx, server, timeout)
		if err == nil {
			return addr, nil
		}
		if ctx.Err() != nil {
			return netip.AddrPort{}, ctx.Err()
		}
		lastErr = err
	}

	return netip.AddrPort{}, fmt.Errorf("%w: %v (%v)", ErrTimeout, server, lastErr)
}

func (c *Client) attempt(
	ctx context.Context,
	server netip.AddrPort,
	timeout time.Duration,
) (netip.AddrPort, error) {
	message, err := pion.Build(pion.TransactionID, pion.BindingRequest)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: so'rov qurish: %w", err)
	}

	reply := make(chan netip.AddrPort, 1)

	c.mu.Lock()
	c.pending[message.TransactionID] = reply
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pending, message.TransactionID)
		c.mu.Unlock()
	}()

	if err := c.send(message.Raw, server); err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: yuborish: %w", err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return netip.AddrPort{}, ctx.Err()
	case <-timer.C:
		return netip.AddrPort{}, ErrTimeout
	case addr := <-reply:
		return addr, nil
	}
}

// Handle kelgan paketni STUN javobi sifatida qayta ishlaydi.
//
// `true` qaytarsa paket bizniki edi va boshqa ishlovchiga
// berilmasligi kerak.
func (c *Client) Handle(payload []byte) bool {
	if !IsMessage(payload) {
		return false
	}

	message := &pion.Message{Raw: append([]byte(nil), payload...)}
	if err := message.Decode(); err != nil {
		return false
	}

	// Faqat o'zimiz so'ragan javoblarni qabul qilamiz. Kutilmagan
	// tranzaksiya ID'si — bu boshqa birov yuborgan paket.
	c.mu.Lock()
	reply, expected := c.pending[message.TransactionID]
	c.mu.Unlock()

	if !expected {
		return true // STUN xabari edi, lekin bizniki emas
	}

	var mapped pion.XORMappedAddress
	if err := mapped.GetFrom(message); err != nil {
		return true
	}

	addr, ok := netip.AddrFromSlice(mapped.IP)
	if !ok {
		return true
	}

	select {
	case reply <- netip.AddrPortFrom(addr.Unmap(), uint16(mapped.Port)):
	default:
	}

	return true
}

// Pending — javob kutayotgan so'rovlar soni (diagnostika uchun).
func (c *Client) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}
