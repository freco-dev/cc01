// Package events klient (cc01 CLI) va edge server o'rtasidagi boshqaruv
// protokolini amalga oshiradi.
//
// Simli format proto/cc01/v1/tunnel.proto da ta'riflangan:
//
//	Ulanish preambulasi — klient → server, bir marta:
//	  magic   [4]byte = "CC01"
//	  version uint8   = 1
//
//	Keyin har bir freym, ikkala yo'nalishda:
//	  length  uint32 little-endian  (payload uzunligi)
//	  payload Frame                 (protobuf)
//
// Preambula ataylab qo'shilgan: eski gob protokoli 2 baytli uzunlik bilan
// boshlangan, shuning uchun magic mos kelmaydi va server aniq xato bilan
// rad etadi — noto'g'ri parse qilingan baytlar bilan ishlashga urinmaydi.
package events

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	cc01v1 "github.com/freco-dev/cc01/core-server/gen/cc01/v1"
	"google.golang.org/protobuf/proto"
)

const (
	// Magic — ulanish boshidagi imzo.
	Magic = "CC01"

	// Version — protokol versiyasi. Mos kelmasa ulanish rad etiladi.
	Version byte = 1

	// MaxFrameSize — bitta freymning yuqori chegarasi. Buzuq yoki yovuz
	// klient uzunlik maydoniga katta son yozib, serverda xotira
	// ajratishga majburlay olmasligi uchun.
	MaxFrameSize = 1 << 20 // 1 MiB
)

var (
	// ErrBadMagic — klient eski protokolda yoki umuman boshqa protokolda
	// gaplashmoqda.
	ErrBadMagic = errors.New("cc01: noto'g'ri protokol imzosi (eski klient?)")

	// ErrBadVersion — protokol versiyasi qo'llab-quvvatlanmaydi.
	ErrBadVersion = errors.New("cc01: protokol versiyasi qo'llab-quvvatlanmaydi")

	// ErrFrameTooLarge — freym MaxFrameSize dan katta.
	ErrFrameTooLarge = errors.New("cc01: freym juda katta")
)

// WritePreamble klient ulanish ochgach birinchi bo'lib shuni yuboradi.
func WritePreamble(w io.Writer) error {
	if _, err := w.Write([]byte(Magic)); err != nil {
		return err
	}
	_, err := w.Write([]byte{Version})
	return err
}

// ReadPreamble server tomonda ulanishning boshini tekshiradi.
func ReadPreamble(r io.Reader) error {
	buf := make([]byte, len(Magic)+1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	if string(buf[:len(Magic)]) != Magic {
		return ErrBadMagic
	}
	if buf[len(Magic)] != Version {
		return fmt.Errorf("%w: %d (kutilgan %d)", ErrBadVersion, buf[len(Magic)], Version)
	}
	return nil
}

// WriteFrame bitta boshqaruv freymini yozadi.
func WriteFrame(w io.Writer, frame *cc01v1.Frame) error {
	payload, err := proto.Marshal(frame)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}

	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(payload)))

	// Sarlavha va payload bitta Write bilan: qisman yozilgan freym
	// qoldirmaslik uchun (bir nechta goroutine yozayotgan bo'lsa muhim).
	if _, err := w.Write(append(header, payload...)); err != nil {
		return err
	}
	return nil
}

// ReadFrame bitta boshqaruv freymini o'qiydi.
func ReadFrame(r io.Reader) (*cc01v1.Frame, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	size := binary.LittleEndian.Uint32(header)
	if size > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d bayt", ErrFrameTooLarge, size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	var frame cc01v1.Frame
	if err := proto.Unmarshal(payload, &frame); err != nil {
		return nil, err
	}
	return &frame, nil
}

// ─────────────────────── qulaylik funksiyalari ───────────────────────

func WriteTunnelRequested(w io.Writer, msg *cc01v1.TunnelRequested) error {
	return WriteFrame(w, &cc01v1.Frame{
		Body: &cc01v1.Frame_TunnelRequested{TunnelRequested: msg},
	})
}

func WriteTunnelOpened(w io.Writer, msg *cc01v1.TunnelOpened) error {
	return WriteFrame(w, &cc01v1.Frame{
		Body: &cc01v1.Frame_TunnelOpened{TunnelOpened: msg},
	})
}

func WriteConnectionReceived(w io.Writer, msg *cc01v1.ConnectionReceived) error {
	return WriteFrame(w, &cc01v1.Frame{
		Body: &cc01v1.Frame_ConnectionReceived{ConnectionReceived: msg},
	})
}

// WriteError klientga rad javobini yuboradi va o'sha xatoni qaytaradi,
// shunda chaqiruvchi uni log'ga yozishi mumkin.
func WriteError(w io.Writer, code, format string, args ...any) error {
	message := fmt.Sprintf(format, args...)

	_ = WriteTunnelOpened(w, &cc01v1.TunnelOpened{
		ErrorCode:    code,
		ErrorMessage: message,
	})

	return fmt.Errorf("%s: %s", code, message)
}
