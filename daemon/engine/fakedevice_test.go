package engine

import (
	"errors"
	"sync"

	"github.com/freco-dev/cc01/daemon/tun"
)

// fakeDevice — TUN o'rniga kanal asosidagi soxta qurilma.
//
// Haqiqiy TUN CAP_NET_ADMIN talab qiladi; datapath mantiqini esa
// imtiyozsiz sinash kerak. Haqiqiy qurilma bilan integratsiya
// alohida — konteynerdagi testlarda (`make test-linux`).
type fakeDevice struct {
	outbound chan []byte // testdan engine'ga (TUN'dan o'qilgandek)
	inbound  chan []byte // engine'dan testga (TUN'ga yozilgandek)

	closeOnce sync.Once
	closed    chan struct{}
}

func newFakeDevice() *fakeDevice {
	return &fakeDevice{
		outbound: make(chan []byte, 64),
		inbound:  make(chan []byte, 64),
		closed:   make(chan struct{}),
	}
}

func (d *fakeDevice) Name() string   { return "fake0" }
func (d *fakeDevice) BatchSize() int { return 8 }

func (d *fakeDevice) NewBuffers() ([][]byte, []int) {
	bufs := make([][]byte, d.BatchSize())
	for i := range bufs {
		bufs[i] = make([]byte, tun.Offset+tun.DefaultMTU+64)
	}
	return bufs, make([]int, d.BatchSize())
}

// Read engine'ga paket beradi — yadro TUN'ga yozgandek.
func (d *fakeDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < tun.Offset {
		return 0, tun.ErrOffsetTooSmall
	}

	select {
	case <-d.closed:
		return 0, errors.New("fake device: yopilgan")
	case packet := <-d.outbound:
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	}
}

// Write engine yozgan paketni testga uzatadi — yadro o'qigandek.
func (d *fakeDevice) Write(bufs [][]byte, offset int) (int, error) {
	if offset < tun.Offset {
		return 0, tun.ErrOffsetTooSmall
	}

	for _, buf := range bufs {
		packet := append([]byte(nil), buf[offset:]...)
		select {
		case <-d.closed:
			return 0, errors.New("fake device: yopilgan")
		case d.inbound <- packet:
		default:
			// Test o'qimayapti — tashlaymiz, bloklanmaymiz.
		}
	}
	return len(bufs), nil
}

// inject paketni engine'ning chiqish yo'liga yuboradi.
func (d *fakeDevice) inject(packet []byte) {
	select {
	case d.outbound <- packet:
	case <-d.closed:
	}
}

// Close bloklangan Read'ni uyg'otadi va idempotent.
func (d *fakeDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}
