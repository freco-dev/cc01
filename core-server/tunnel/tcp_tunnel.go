package tunnel

import (
	"fmt"
	"net"

	"github.com/freco-dev/cc01/core-server/server"
)

type TCPTunnel struct {
	tunnel
	publicServer server.TCPServer
}

func NewTCP(hostname string, eventConn net.Conn, maxConsLimit int) (*TCPTunnel, error) {
	t := &TCPTunnel{
		tunnel: newTunnel(hostname, eventConn, maxConsLimit),
	}
	if err := t.privateServer.Init(0, "tcp_tunnel_private_server"); err != nil {
		return t, fmt.Errorf("error init private server: %w", err)
	}
	if err := t.publicServer.Init(0, "tcp_tunnel_public_server"); err != nil {
		return t, fmt.Errorf("error init public server: %w", err)
	}
	return t, nil
}

func (t *TCPTunnel) Protocol() string {
	return "tcp"
}

func (t *TCPTunnel) PublicServerPort() uint16 {
	return t.publicServer.Port()
}

func (t *TCPTunnel) Open() {
	go t.publicServer.Start(t.publicConnectionHandler)
	go t.privateServer.Start(t.privateConnectionHandler)
}

// Close ommaviy serverni to'xtatadi va qolganini ichki tunnel.Close ga
// topshiradi (o'sha sync.Once ostida — qayta chaqirish xavfsiz).
func (t *TCPTunnel) Close() {
	t.closeWith(func() { _ = t.publicServer.Stop() })
}
