package relay

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/freco-dev/cc01/daemon/noise"
)

var (
	// ErrNotConnected — relay bilan sessiya hali o'rnatilmagan.
	ErrNotConnected = errors.New("relay: sessiya yo'q")

	// ErrHandshakeTimeout — relay javob bermadi.
	ErrHandshakeTimeout = errors.New("relay: handshake javobsiz qoldi")
)

// SendFunc paketni relayga yuboradi.
type SendFunc func(payload []byte, to netip.AddrPort) error

// Client — relay bilan sessiyani ushlab turuvchi.
//
// Klient o'z soketini ochmaydi: u datapath soketidan foydalanadi.
// Sabab STUN bilan bir xil — NAT bog'lanishi soketga bog'langan, va
// relayga boshqa soketdan ulanish alohida bog'lanish yaratardi.
type Client struct {
	identity *noise.Identity
	relayKey noise.PublicKey
	endpoint netip.AddrPort
	send     SendFunc

	mu        sync.Mutex
	handshake *noise.Handshake
	session   *noise.Session
	ready     chan struct{}
}

// ClientOptions — klient sozlamalari.
type ClientOptions struct {
	// Identity — bizning kalit juftimiz.
	Identity *noise.Identity

	// RelayKey — relayning public kaliti. IK patterni uni OLDINDAN
	// talab qiladi; u NetworkMap dagi `relays[]` dan keladi.
	RelayKey noise.PublicKey

	// Endpoint — relayning underlay manzili.
	Endpoint netip.AddrPort

	// Send — datapath soketining yuborish funksiyasi.
	Send SendFunc
}

func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Identity == nil {
		return nil, errors.New("relay: identity berilmagan")
	}
	if opts.RelayKey.IsZero() {
		return nil, errors.New("relay: relay public kaliti berilmagan")
	}
	if !opts.Endpoint.IsValid() {
		return nil, fmt.Errorf("relay: endpoint yaroqsiz: %v", opts.Endpoint)
	}
	if opts.Send == nil {
		return nil, errors.New("relay: yuborish funksiyasi berilmagan")
	}

	return &Client{
		identity: opts.Identity,
		relayKey: opts.RelayKey,
		endpoint: opts.Endpoint,
		send:     opts.Send,
		ready:    make(chan struct{}),
	}, nil
}

// NodeID — bizning identifikatorimiz.
func (c *Client) NodeID() NodeID { return NodeIDFor(c.identity.PublicKey()) }

// Endpoint — relayning manzili.
func (c *Client) Endpoint() netip.AddrPort { return c.endpoint }

// Connect relay bilan Noise sessiyasini o'rnatadi.
//
// Javob `Handle` orqali keladi: datapath soketini engine o'qiydi va
// relay paketlarini bizga uzatadi.
func (c *Client) Connect(ctx context.Context) error {
	handshake, err := noise.StartInitiator(c.identity, c.relayKey)
	if err != nil {
		return fmt.Errorf("relay: handshake boshlanmadi: %w", err)
	}

	initiation, err := handshake.WriteInitiation()
	if err != nil {
		return fmt.Errorf("relay: initiation: %w", err)
	}

	c.mu.Lock()
	c.handshake = handshake
	c.mu.Unlock()

	if err := c.send(initiation, c.endpoint); err != nil {
		return fmt.Errorf("relay: initiation yuborilmadi: %w", err)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ready:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("%w: %v", ErrHandshakeTimeout, c.endpoint)
	}
}

// Connected — sessiya o'rnatilganmi.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session != nil
}

// LocalIndex — bizning sessiya indeksimiz; relaydan kelgan paketlar
// shu indeks bilan keladi.
func (c *Client) LocalIndex() (uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil {
		return 0, false
	}
	return c.session.LocalIndex(), true
}

// Send ichki paketni relay orqali qabul qiluvchiga yuboradi.
func (c *Client) Send(destination NodeID, inner []byte) error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return ErrNotConnected
	}

	frame, err := Wrap(destination, inner)
	if err != nil {
		return err
	}

	sealed, err := session.Seal(noise.TypeRelayWrap, frame)
	if err != nil {
		return fmt.Errorf("relay: shifrlash: %w", err)
	}

	return c.send(sealed, c.endpoint)
}

// Keepalive relay tomondagi sessiyani va NAT bog'lanishini tirik
// ushlab turadi.
func (c *Client) Keepalive() error {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil {
		return ErrNotConnected
	}

	packet, err := session.Seal(noise.TypeKeepalive, nil)
	if err != nil {
		return err
	}
	return c.send(packet, c.endpoint)
}

// Received — relaydan kelgan ichki paket.
type Received struct {
	// From — jo'natuvchining node_id si. Uni relay o'z sessiyasidan
	// oladi, klient yuborgan qiymatdan emas.
	From NodeID

	// Inner — peerlar o'rtasidagi shifrlangan paket. Relay uni
	// ocha olmagan.
	Inner []byte
}

// Handle relaydan kelgan paketni qayta ishlaydi.
//
// Ikkinchi qiymat — paket bizniki edimi. `true` bo'lsa uni boshqa
// ishlovchiga bermaslik kerak.
func (c *Client) Handle(packet []byte, from netip.AddrPort) (*Received, bool) {
	if from != c.endpoint {
		return nil, false
	}

	header, err := noise.ParseHeader(packet)
	if err != nil {
		return nil, false
	}

	switch header.Type {
	case noise.TypeHandshakeResp:
		return nil, c.completeHandshake(packet)

	case noise.TypeRelayWrap:
		return c.unwrap(header, packet)

	default:
		return nil, false
	}
}

func (c *Client) completeHandshake(packet []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.handshake == nil || c.session != nil {
		return false
	}

	session, err := c.handshake.ReadResponse(packet)
	if err != nil {
		return false
	}

	c.session = session
	c.handshake = nil
	close(c.ready)

	return true
}

func (c *Client) unwrap(header noise.Header, packet []byte) (*Received, bool) {
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()

	if session == nil || header.ReceiverIndex != session.LocalIndex() {
		return nil, false
	}

	_, payload, err := session.Open(packet)
	if err != nil {
		return nil, true
	}

	sender, inner, err := Unwrap(payload)
	if err != nil {
		return nil, true
	}

	// Nusxa: `inner` kirish buferining bo'lagi, u qayta ishlatiladi.
	return &Received{From: sender, Inner: append([]byte(nil), inner...)}, true
}
