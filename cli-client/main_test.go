package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/freco-dev/cc01/core-server/events"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

func TestHandleFrame_ClosureFrameReturnsError(t *testing.T) {
	frame := &cc01v1.Frame{Body: &cc01v1.Frame_TunnelOpened{TunnelOpened: &cc01v1.TunnelOpened{
		ErrorCode:    "TOKEN_REVOKED",
		ErrorMessage: "token bekor qilingan",
	}}}

	act, err := handleFrame(frame)

	var closed *tunnelClosedError
	if !errors.As(err, &closed) {
		t.Fatalf("handleFrame xatosi = %v, *tunnelClosedError kutilgan", err)
	}
	if closed.Code != "TOKEN_REVOKED" || closed.Msg != "token bekor qilingan" {
		t.Fatalf("tunnelClosedError = %+v", closed)
	}
	if got, want := err.Error(), "tunnel yopildi: TOKEN_REVOKED: token bekor qilingan"; got != want {
		t.Fatalf("Error() = %q, kutilgan %q", got, want)
	}
	if act.bridge {
		t.Fatal("yopilish freymi ko'prik ochmasligi kerak")
	}
}

func TestHandleFrame_UnknownFrameIgnored(t *testing.T) {
	cases := map[string]*cc01v1.Frame{
		"bo'sh freym": {},
		"klientga kutilmagan TunnelRequested": {Body: &cc01v1.Frame_TunnelRequested{
			TunnelRequested: &cc01v1.TunnelRequested{},
		}},
		// Xatosiz TunnelOpened — yopilish emas, e'tiborsiz.
		"xatosiz TunnelOpened": {Body: &cc01v1.Frame_TunnelOpened{
			TunnelOpened: &cc01v1.TunnelOpened{Hostname: "a.example.com"},
		}},
		// Faqat kod, xabarsiz — eski xulq-atvor: `error_message` hal qiladi.
		"faqat error_code": {Body: &cc01v1.Frame_TunnelOpened{
			TunnelOpened: &cc01v1.TunnelOpened{ErrorCode: "X"},
		}},
	}

	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			act, err := handleFrame(frame)
			if err != nil {
				t.Fatalf("handleFrame xatosi = %v, nil kutilgan", err)
			}
			if act != (action{}) {
				t.Fatalf("action = %+v, nol qiymat kutilgan", act)
			}
		})
	}
}

func TestHandleFrame_ConnectionReceivedBridges(t *testing.T) {
	frame := &cc01v1.Frame{Body: &cc01v1.Frame_ConnectionReceived{
		ConnectionReceived: &cc01v1.ConnectionReceived{
			ClientIp:   net.IPv4(203, 0, 113, 7).To4(),
			ClientPort: 54321,
		},
	}}

	act, err := handleFrame(frame)
	if err != nil {
		t.Fatalf("handleFrame xatosi = %v", err)
	}
	if want := (action{bridge: true, clientPort: 54321}); act != want {
		t.Fatalf("action = %+v, kutilgan %+v", act, want)
	}
}

func TestHandleFrame_RateLimitedConnectionIgnored(t *testing.T) {
	frame := &cc01v1.Frame{Body: &cc01v1.Frame_ConnectionReceived{
		ConnectionReceived: &cc01v1.ConnectionReceived{
			ClientIp:    net.IPv4(203, 0, 113, 7).To4(),
			ClientPort:  54321,
			RateLimited: true,
		},
	}}

	act, err := handleFrame(frame)
	if err != nil {
		t.Fatalf("handleFrame xatosi = %v", err)
	}
	if act.bridge {
		t.Fatal("limitga tushgan ulanish uchun ko'prik ochilmasligi kerak")
	}
}

// Yopilish freymi ochiq ko'prik bo'lsa ham `serveTunnel` ni darhol
// tugatadi: ko'priklarni edge o'zi yopadi, klient ularni kutmaydi.
func TestServeTunnel_ClosureFrameReturnsWithoutWaitingForBridges(t *testing.T) {
	// Xususiy port: ulanishni qabul qiladi, lekin hech qachon yopmaydi —
	// ko'prik `serveTunnel` tugaguncha ochiq qoladi.
	private, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer private.Close()
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()

	accepted := make(chan net.Conn, 2)
	for _, l := range []net.Listener{private, local} {
		go func(l net.Listener) {
			c, err := l.Accept()
			if err == nil {
				accepted <- c
			}
		}(l)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	privatePort := uint16(private.Addr().(*net.TCPAddr).Port)
	done := make(chan error, 1)
	go func() {
		done <- serveTunnel(client, "127.0.0.1", local.Addr().String(), privatePort)
	}()

	if err := events.WriteConnectionReceived(server, &cc01v1.ConnectionReceived{
		ClientIp:   net.IPv4(203, 0, 113, 7).To4(),
		ClientPort: 40000,
	}); err != nil {
		t.Fatal(err)
	}

	// Ko'prik ikkala tomonga ham ulangunicha kutamiz — u ochiq turibdi.
	var bridged []net.Conn
	for range 2 {
		select {
		case c := <-accepted:
			bridged = append(bridged, c)
		case <-time.After(5 * time.Second):
			t.Fatal("ko'prik ochilmadi")
		}
	}
	// Edge rolida: ko'prikni test oxirida yopamiz.
	defer func() {
		for _, c := range bridged {
			_ = c.Close()
		}
	}()

	if err := events.WriteTunnelOpened(server, &cc01v1.TunnelOpened{
		ErrorCode:    "PLAN_SUSPENDED",
		ErrorMessage: "tarif to'xtatilgan",
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		var closed *tunnelClosedError
		if !errors.As(err, &closed) || closed.Code != "PLAN_SUSPENDED" {
			t.Fatalf("serveTunnel xatosi = %v, PLAN_SUSPENDED kutilgan", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveTunnel yopilish freymidan keyin tugamadi")
	}
}
