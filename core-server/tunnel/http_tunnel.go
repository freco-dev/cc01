package tunnel

import (
	"net"
)

const DefaultHttpPort = 80

type HTTPTunnel struct {
	tunnel
}

func NewHTTP(hostname string, eventConn net.Conn, maxConsLimit int) (*HTTPTunnel, error) {
	t := &HTTPTunnel{
		tunnel: newTunnel(hostname, eventConn, maxConsLimit),
	}
	if err := t.privateServer.Init(0, "http-tunnel-private-server"); err != nil {
		return t, err
	}
	return t, nil
}

func (t *HTTPTunnel) Protocol() string {
	return "http"
}

func (t *HTTPTunnel) PublicServerPort() uint16 {
	return DefaultHttpPort
}

func (t *HTTPTunnel) Open() {
	go t.privateServer.Start(t.privateConnectionHandler)
}

// PublicConnectionHandler ommaviy HTTP ulanishni qabul qiladi.
// initialBuffer (Host sarlavhasini aniqlash uchun o'qilgan baytlar)
// ulanish bilan birga consMx ostida saqlanadi; rad etilgan ulanishning
// buferi xaritada qolib ketmaydi.
func (t *HTTPTunnel) PublicConnectionHandler(publicCon net.Conn, initialBuffer []byte) error {
	return t.acceptPublic(publicCon, initialBuffer)
}
