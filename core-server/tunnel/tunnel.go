package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/freco-dev/cc01/core-server/events"
	"github.com/freco-dev/cc01/core-server/server"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

type Tunnel interface {
	Open()
	Close()
	Hostname() string
	Protocol() string
	PublicServerPort() uint16
	PrivateServerPort() uint16

	// SetMaxConns ochiq tunnelning ulanish limitini jonli o'zgartiradi
	// (tarif yangilanishi). Yangi qiymat faqat YANGI ulanishlarga
	// ta'sir qiladi: mavjud ulanishlar uzilmaydi.
	SetMaxConns(n int)
	MaxConns() int

	// WriteOpened klientga TunnelOpened freymini yuboradi va shundan
	// keyingina tunnel ommaviy ulanishlarni qabul qila boshlaydi.
	WriteOpened(msg *cc01v1.TunnelOpened) error

	// Notify ochiq tunnel yopilayotganini bildiruvchi freymni
	// (TunnelOpened{error_code, error_message}) yuboradi.
	Notify(code, msg string) error
}

// ErrNotOpened — TunnelOpened freymi hali yuborilmagan (yoki tunnel
// yopilish bildirishnomasidan keyin) kelgan ommaviy ulanish.
var ErrNotOpened = errors.New("tunnel hali ochilmagan")

// ErrClosed — Close() dan keyin kelgan ommaviy ulanish.
var ErrClosed = errors.New("tunnel yopilgan")

// ErrEventConnBroken — boshqaruv kanaliga oldingi yozish muvaffaqiyatsiz
// bo'lgan (masalan, klient o'qimay qo'ygani uchun muddat tugagan): kanal
// yopilgan va unga boshqa freym yozilmaydi.
var ErrEventConnBroken = errors.New("boshqaruv kanali uzilgan")

// EventWriteTimeout — boshqaruv kanaliga bitta freym yozish uchun eng
// ko'p vaqt. O'qimay qo'ygan (to'xtatilgan yoki yovuz) klient yozuvchini
// abadiy ushlab tura olmasligi kerak: aks holda Notify (bekor qilish),
// SetMaxConns va Close ham uning ortida qotib qolardi.
const EventWriteTimeout = 5 * time.Second

type tunnel struct {
	hostname string

	// eventWriterMx boshqaruv kanaliga yoziladigan BARCHA freymlarni
	// tartiblaydi. Qulf tartibi: avval eventWriterMx, keyin consMx.
	//
	// ⚠️ Tarmoqqa yozish HECH QACHON consMx ostida bajarilmaydi va har
	// bir yozishning muddati bor (writeTimeout): to'xtab qolgan klient
	// eng ko'pi bilan writeTimeout davomida faqat eventWriterMx ni
	// ushlaydi, consMx (Close, SetMaxConns, juftlash) esa bo'sh qoladi.
	eventConn     net.Conn
	eventWriterMx sync.Mutex
	writeTimeout  time.Duration
	opened        bool // eventWriterMx ostida
	eventBroken   bool // eventWriterMx ostida

	privateServer server.TCPServer

	// Quyidagilarning hammasi consMx ostida o'qiladi va yoziladi.
	consMx        sync.Mutex
	maxConsLimit  int
	closed        bool
	publicCons    map[uint16]net.Conn
	initialBuffer map[uint16][]byte
	pairs         map[net.Conn]net.Conn // ommaviy -> xususiy (ko'priklangan)

	closeOnce sync.Once
}

func newTunnel(hostname string, eventConn net.Conn, maxConsLimit int) tunnel {
	return tunnel{
		hostname:      hostname,
		maxConsLimit:  maxConsLimit,
		eventConn:     eventConn,
		writeTimeout:  EventWriteTimeout,
		publicCons:    make(map[uint16]net.Conn),
		initialBuffer: make(map[uint16][]byte),
		pairs:         make(map[net.Conn]net.Conn),
	}
}

// Close xususiy serverni to'xtatadi, juftlanmagan ommaviy ulanishlarni
// va ko'priklangan BARCHA juftliklarni yopadi. Qayta chaqirish xavfsiz.
func (t *tunnel) Close() {
	t.closeWith(nil)
}

// closeWith Close ni bir marta bajaradi; extra (masalan, TCP tunnelning
// ommaviy serverini to'xtatish) o'sha sync.Once ichida birinchi bo'lib
// ishlaydi.
func (t *tunnel) closeWith(extra func()) {
	t.closeOnce.Do(func() {
		if extra != nil {
			extra()
		}
		t.privateServer.Stop()

		t.consMx.Lock()
		defer t.consMx.Unlock()
		t.closed = true
		for port, con := range t.publicCons {
			con.Close()
			delete(t.publicCons, port)
			delete(t.initialBuffer, port)
		}
		for publicCon, privateCon := range t.pairs {
			publicCon.Close()
			privateCon.Close()
			delete(t.pairs, publicCon)
		}
	})
}

func (t *tunnel) Hostname() string {
	return t.hostname
}

func (t *tunnel) PrivateServerPort() uint16 {
	return t.privateServer.Port()
}

func (t *tunnel) SetMaxConns(n int) {
	t.consMx.Lock()
	defer t.consMx.Unlock()
	t.maxConsLimit = n
}

func (t *tunnel) MaxConns() int {
	t.consMx.Lock()
	defer t.consMx.Unlock()
	return t.maxConsLimit
}

// writeEvent bitta freymni muddat bilan yozadi. Chaqiruvchi
// eventWriterMx ni ushlab turadi, consMx ni esa USHLAMAYDI.
//
// Yozish muvaffaqiyatsiz bo'lsa (muddat tugashi ham) freym qisman
// ketgan bo'lishi mumkin — oqim endi tiklanmaydi. Shuning uchun kanal
// yopiladi: klientni kutayotgan o'quvchi (cc01.go) buni ko'radi va
// tunnelni odatiy yo'l bilan yopadi; keyingi yozishlar darhol rad etiladi.
func (t *tunnel) writeEvent(write func(io.Writer) error) error {
	if t.eventBroken {
		return ErrEventConnBroken
	}
	_ = t.eventConn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
	if err := write(t.eventConn); err != nil {
		t.eventBroken = true
		t.opened = false
		_ = t.eventConn.Close()
		return err
	}
	return nil
}

// WriteOpened TunnelOpened freymini yozadi va muvaffaqiyatli bo'lsa,
// tunnelni ommaviy ulanishlar uchun ochadi. Shu tufayli ConnectionReceived
// freymi hech qachon TunnelOpened dan oldin ketmaydi.
func (t *tunnel) WriteOpened(msg *cc01v1.TunnelOpened) error {
	t.eventWriterMx.Lock()
	defer t.eventWriterMx.Unlock()
	if err := t.writeEvent(func(w io.Writer) error {
		return events.WriteTunnelOpened(w, msg)
	}); err != nil {
		return err
	}
	t.opened = true
	return nil
}

// Notify yopilish bildirishnomasini yozadi. Shundan keyin yangi ommaviy
// ulanishlar qabul qilinmaydi — bildirishnomadan keyin boshqa freym
// ketmaydi. Eski klientlar bu freymni e'tiborsiz qoldiradi.
func (t *tunnel) Notify(code, msg string) error {
	if msg == "" {
		// Klient yopilishni error_message bo'shligiga qarab ajratadi.
		msg = code
	}
	t.eventWriterMx.Lock()
	defer t.eventWriterMx.Unlock()
	t.opened = false
	return t.writeEvent(func(w io.Writer) error {
		return events.WriteTunnelOpened(w, &cc01v1.TunnelOpened{
			ErrorCode:    code,
			ErrorMessage: msg,
		})
	})
}

func (t *tunnel) publicConnectionHandler(publicCon net.Conn) error {
	return t.acceptPublic(publicCon, nil)
}

// acceptPublic ommaviy ulanishni ro'yxatga oladi va klientga
// ConnectionReceived yuboradi. initialBuffer (HTTP: sarlavhani aniqlash
// uchun o'qib olingan baytlar) ulanish bilan birga, o'sha qulf ostida
// saqlanadi.
//
// O'rin (limit) consMx ostida band qilinadi, freym esa consMx QO'YIB
// YUBORILGANDAN keyin yoziladi: to'xtab qolgan klient Close, SetMaxConns
// va juftlashni bloklay olmaydi.
func (t *tunnel) acceptPublic(publicCon net.Conn, initialBuffer []byte) error {
	ip := publicCon.RemoteAddr().(*net.TCPAddr).IP
	port := uint16(publicCon.RemoteAddr().(*net.TCPAddr).Port)

	t.eventWriterMx.Lock()
	defer t.eventWriterMx.Unlock()

	// TunnelOpened hali yuborilmagan: klient bu ulanishni kutmayapti,
	// shuning uchun freym yozmasdan yopamiz.
	if !t.opened {
		publicCon.Close()
		return fmt.Errorf("[tunnel-not-opened]: %s: %w", t.hostname, ErrNotOpened)
	}

	t.consMx.Lock()
	if t.closed {
		t.consMx.Unlock()
		publicCon.Close()
		return fmt.Errorf("[tunnel-closed]: %s: %w", t.hostname, ErrClosed)
	}
	if len(t.publicCons) >= t.maxConsLimit {
		t.consMx.Unlock()
		publicCon.Close()
		_ = t.writeEvent(func(w io.Writer) error {
			return events.WriteConnectionReceived(w, &cc01v1.ConnectionReceived{
				ClientIp:    ip,
				RateLimited: true,
			})
		})
		return fmt.Errorf("[connections-limit-reached]: %s", t.hostname)
	}
	t.publicCons[port] = publicCon
	if len(initialBuffer) > 0 {
		t.initialBuffer[port] = initialBuffer
	}
	t.consMx.Unlock()

	if err := t.writeEvent(func(w io.Writer) error {
		return events.WriteConnectionReceived(w, &cc01v1.ConnectionReceived{
			ClientIp:   ip,
			ClientPort: uint32(port),
		})
	}); err != nil {
		// Band qilingan o'rin bo'shatiladi (Close uni allaqachon olib
		// tashlagan bo'lishi mumkin).
		t.consMx.Lock()
		if t.publicCons[port] == publicCon {
			delete(t.publicCons, port)
			delete(t.initialBuffer, port)
		}
		t.consMx.Unlock()
		publicCon.Close()
		return fmt.Errorf("[event-write-failed]: %s: %w", t.hostname, err)
	}
	return nil
}

func (t *tunnel) privateConnectionHandler(privateCon net.Conn) error {
	defer privateCon.Close()
	buffer := make([]byte, 2)
	if _, err := privateCon.Read(buffer); err != nil {
		return err
	}

	port := binary.LittleEndian.Uint16(buffer)
	t.consMx.Lock()
	publicCon, found := t.publicCons[port]
	if !found {
		t.consMx.Unlock()
		return errors.New("public connection not found, cannot pair")
	}
	delete(t.publicCons, port)
	initialBuffer := t.initialBuffer[port]
	delete(t.initialBuffer, port)
	// Juftlik shu qulf ostida ro'yxatga olinadi: Close() uni albatta ko'radi.
	t.pairs[publicCon] = privateCon
	t.consMx.Unlock()

	defer func() {
		t.consMx.Lock()
		delete(t.pairs, publicCon)
		t.consMx.Unlock()
	}()
	defer publicCon.Close()

	if len(initialBuffer) > 0 {
		if _, err := privateCon.Write(initialBuffer); err != nil {
			return err
		}
	}

	go Bind(publicCon, privateCon, nil)
	Bind(privateCon, publicCon, nil)
	return nil
}

func Bind(src net.Conn, dst net.Conn, debug io.Writer) error {
	defer src.Close()
	defer dst.Close()
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			if debug != nil {
				_, _ = debug.Write(buf[:n])
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}
