package server

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestTCPServerInit(t *testing.T) {
	s := &TCPServer{}
	err := s.Init(0, "test_server")
	defer s.Stop()

	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}

	if s.listener == nil {
		t.Fatalf("listener not created")
	}
}

func TestTCPServerPort(t *testing.T) {
	s := &TCPServer{}
	defer s.Stop()

	err := s.Init(0, "test_server")
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}

	port := s.Port()
	if port == 0 {
		t.Fatalf("expected an assigned port, got %d", port)
	}
}

// startServer Start ni alohida goroutine'da ishga tushiradi; qaytgan
// kanal Start tugaganda yopiladi.
func startServer(s *TCPServer) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Start(func(c net.Conn) error { return c.Close() })
	}()
	return done
}

func waitStart(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Start Stop dan keyin qaytmadi")
	}
}

// Stop Accept sikli bilan parallel ishlaydi (tunnel yopilishi). Avval
// Stop listener maydonini sinxronizatsiyasiz nil qilardi: -race buni
// ushlaydi, aks holda keyingi aylanishda nil.Accept() panic bo'lib, butun
// edge jarayoni yiqilardi.
func TestTCPServer_StopWhileAccepting(t *testing.T) {
	for i := 0; i < 100; i++ {
		var s TCPServer
		if err := s.Init(0, "test_server"); err != nil {
			t.Fatal(err)
		}
		addr := fmt.Sprintf("127.0.0.1:%d", s.Port())
		done := startServer(&s)

		stopDial := make(chan struct{})
		dialed := make(chan struct{})
		go func() {
			defer close(dialed)
			for {
				select {
				case <-stopDial:
					return
				default:
				}
				if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
					_ = c.Close()
				}
			}
		}()

		time.Sleep(time.Millisecond)
		if err := s.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		waitStart(t, done)
		close(stopDial)
		<-dialed

		if p := s.Port(); p != 0 {
			t.Fatalf("Stop dan keyin Port() 0 bo'lishi kerak, olindi %d", p)
		}
	}
}

// Start dan OLDIN chaqirilgan Stop (masalan, Open'dan oldin yopilgan
// tunnel) Start ni nil listener bilan panic'ga olib bormasligi kerak.
func TestTCPServer_StartAfterStopReturns(t *testing.T) {
	var s TCPServer
	if err := s.Init(0, "test_server"); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("takroriy Stop: %v", err)
	}
	waitStart(t, startServer(&s))
}
