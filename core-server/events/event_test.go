package events

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	cc01v1 "github.com/freco-dev/cc01/core-server/gen/cc01/v1"
)

func TestPreamble_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePreamble(&buf); err != nil {
		t.Fatalf("yozishda xato: %v", err)
	}
	if err := ReadPreamble(&buf); err != nil {
		t.Fatalf("o'qishda xato: %v", err)
	}
}

// Eski gob protokoli 2 baytli uzunlik bilan boshlangan. Bunday klient
// jimgina noto'g'ri parse qilinmasligi, aniq xato olishi kerak.
func TestPreamble_RejectsLegacyGobClient(t *testing.T) {
	legacy := []byte{0x2a, 0x00, 0xff, 0x81, 0x03}

	err := ReadPreamble(bytes.NewReader(legacy))
	if !errors.Is(err, ErrBadMagic) {
		t.Fatalf("ErrBadMagic kutilgan edi, olindi: %v", err)
	}
}

func TestPreamble_RejectsUnknownVersion(t *testing.T) {
	payload := append([]byte(Magic), 99)

	err := ReadPreamble(bytes.NewReader(payload))
	if !errors.Is(err, ErrBadVersion) {
		t.Fatalf("ErrBadVersion kutilgan edi, olindi: %v", err)
	}
}

func TestFrame_TunnelRequestedRoundTrip(t *testing.T) {
	var buf bytes.Buffer

	sent := &cc01v1.TunnelRequested{
		Protocol:   cc01v1.Protocol_PROTOCOL_HTTP,
		Subdomain:  "myapp",
		Token:      "cc01_live_abc_secret",
		CliVersion: "0.1.0",
	}
	if err := WriteTunnelRequested(&buf, sent); err != nil {
		t.Fatalf("yozishda xato: %v", err)
	}

	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("o'qishda xato: %v", err)
	}

	got := frame.GetTunnelRequested()
	if got == nil {
		t.Fatal("TunnelRequested kutilgan edi")
	}
	if got.GetSubdomain() != sent.GetSubdomain() {
		t.Errorf("subdomain: %q kutilgan, %q olindi", sent.GetSubdomain(), got.GetSubdomain())
	}
	if got.GetToken() != sent.GetToken() {
		t.Errorf("token mos kelmadi")
	}
	if got.GetProtocol() != cc01v1.Protocol_PROTOCOL_HTTP {
		t.Errorf("protokol: %v olindi", got.GetProtocol())
	}
}

func TestFrame_ConnectionReceivedRoundTrip(t *testing.T) {
	var buf bytes.Buffer

	ip := net.ParseIP("2a0e:1234::b7f2")
	if err := WriteConnectionReceived(&buf, &cc01v1.ConnectionReceived{
		ClientIp:   ip,
		ClientPort: 41022,
	}); err != nil {
		t.Fatalf("yozishda xato: %v", err)
	}

	frame, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("o'qishda xato: %v", err)
	}

	got := frame.GetConnectionReceived()
	if got == nil {
		t.Fatal("ConnectionReceived kutilgan edi")
	}
	if !net.IP(got.GetClientIp()).Equal(ip) {
		t.Errorf("IP: %v kutilgan, %v olindi", ip, net.IP(got.GetClientIp()))
	}
	if got.GetClientPort() != 41022 {
		t.Errorf("port: %d olindi", got.GetClientPort())
	}
}

// Uzunlik maydoni yovuz klient tomonidan katta qilib yozilishi mumkin.
// Server bunga ishonib xotira ajratmasligi kerak.
func TestReadFrame_RejectsOversizedLength(t *testing.T) {
	header := []byte{0xff, 0xff, 0xff, 0xff} // ~4 GiB

	_, err := ReadFrame(bytes.NewReader(header))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ErrFrameTooLarge kutilgan edi, olindi: %v", err)
	}
}

func TestReadFrame_TruncatedPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTunnelRequested(&buf, &cc01v1.TunnelRequested{Subdomain: "myapp"}); err != nil {
		t.Fatalf("yozishda xato: %v", err)
	}

	truncated := buf.Bytes()[:buf.Len()-2]

	if _, err := ReadFrame(bytes.NewReader(truncated)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ErrUnexpectedEOF kutilgan edi, olindi: %v", err)
	}
}

func TestWriteError_SendsCodeAndReturnsError(t *testing.T) {
	var buf bytes.Buffer

	err := WriteError(&buf, "SUBDOMAIN_BUSY", "subdomain band: %s", "myapp")
	if err == nil {
		t.Fatal("xato qaytishi kerak edi")
	}

	frame, readErr := ReadFrame(&buf)
	if readErr != nil {
		t.Fatalf("o'qishda xato: %v", readErr)
	}

	opened := frame.GetTunnelOpened()
	if opened == nil {
		t.Fatal("TunnelOpened kutilgan edi")
	}
	if opened.GetErrorCode() != "SUBDOMAIN_BUSY" {
		t.Errorf("xato kodi: %q olindi", opened.GetErrorCode())
	}
	if opened.GetErrorMessage() == "" {
		t.Error("xato xabari bo'sh")
	}
}

func TestFrames_StreamSequentially(t *testing.T) {
	var buf bytes.Buffer

	for i := range 3 {
		if err := WriteConnectionReceived(&buf, &cc01v1.ConnectionReceived{
			ClientPort: uint32(1000 + i),
		}); err != nil {
			t.Fatalf("yozishda xato: %v", err)
		}
	}

	for i := range 3 {
		frame, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("freym %d o'qishda xato: %v", i, err)
		}
		if got := frame.GetConnectionReceived().GetClientPort(); got != uint32(1000+i) {
			t.Errorf("freym %d: port %d kutilgan, %d olindi", i, 1000+i, got)
		}
	}
}
