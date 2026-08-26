package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

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
}

type tunnel struct {
	hostname      string
	maxConsLimit  int
	eventWriter   io.Writer
	eventWriterMx sync.Mutex
	privateServer server.TCPServer
	consMx        sync.Mutex
	publicCons    map[uint16]net.Conn
	initialBuffer map[uint16][]byte
}

func newTunnel(hostname string, eventWriter io.Writer, maxConsLimit int) tunnel {
	return tunnel{
		hostname:      hostname,
		maxConsLimit:  maxConsLimit,
		eventWriter:   eventWriter,
		publicCons:    make(map[uint16]net.Conn),
		initialBuffer: make(map[uint16][]byte),
	}
}

func (t *tunnel) Close() {
	t.privateServer.Stop()
	t.consMx.Lock()
	defer t.consMx.Unlock()
	for port, con := range t.publicCons {
		con.Close()
		delete(t.publicCons, port)
		delete(t.initialBuffer, port)
	}
}

func (t *tunnel) Hostname() string {
	return t.hostname
}

func (t *tunnel) PrivateServerPort() uint16 {
	return t.privateServer.Port()
}

func (t *tunnel) publicConnectionHandler(publicCon net.Conn) error {
	ip := publicCon.RemoteAddr().(*net.TCPAddr).IP
	port := uint16(publicCon.RemoteAddr().(*net.TCPAddr).Port)

	t.eventWriterMx.Lock()
	defer t.eventWriterMx.Unlock()

	t.consMx.Lock()
	defer t.consMx.Unlock()
	if len(t.publicCons) >= t.maxConsLimit {
		publicCon.Close()
		_ = events.WriteConnectionReceived(t.eventWriter, &cc01v1.ConnectionReceived{
			ClientIp:    ip,
			RateLimited: true,
		})
		return fmt.Errorf("[connections-limit-reached]: %s", t.hostname)
	}

	if err := events.WriteConnectionReceived(t.eventWriter, &cc01v1.ConnectionReceived{
		ClientIp:   ip,
		ClientPort: uint32(port),
	}); err != nil {
		return publicCon.Close()
	}
	t.publicCons[port] = publicCon
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
	t.consMx.Unlock()

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
