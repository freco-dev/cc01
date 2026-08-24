package xdp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// Stage — paket qaysi bosqichda tashlangani.
type Stage uint8

const (
	StageBlocklist Stage = 1
	StageRateLimit Stage = 2
	StageAmplify   Stage = 3
)

func (s Stage) String() string {
	switch s {
	case StageBlocklist:
		return "blocklist"
	case StageRateLimit:
		return "tezlik cheklovi"
	case StageAmplify:
		return "amplifikatsiya porti"
	default:
		return "noma'lum"
	}
}

// Event — tashlangan paket haqidagi xabar.
//
// tc dagi hodisadan ALOHIDA tur: XDP boshqa sabablarni ko'radi va
// ularda qoida ID yoki identity yo'q. Bitta tuzilmaga siqish
// maydonlarning yarmini bo'sh qoldirardi.
type Event struct {
	// Uptime — yadro monotonik soati bo'yicha vaqt.
	Uptime time.Duration

	// Src — paketning manba manzili.
	Src netip.Addr

	// Stage — qaysi bosqich tashladi.
	Stage Stage

	// DryRun — hukm qo'llandimi yoki faqat hisoblandimi.
	DryRun bool
}

// eventSize — `struct cc01_xdp_event` ning o'lchami.
const eventSize = 32

func (e Event) String() string {
	action := "tashlandi"
	if e.DryRun {
		action = "tashlangan bo'lardi"
	}
	return fmt.Sprintf("%s: %s (%s)", e.Src, action, e.Stage)
}

// Events hodisalarni o'qish uchun kanal ochadi.
//
// ⚠️ O'qishni kechiktirmang: ring buffer to'lsa yadro yangi
// hodisalarni TASHLAYDI (`StatEventLost` oshadi). Bu ataylab —
// kuzatuv hech qachon filtrlashdan muhimroq emas.
func (f *Filter) Events(ctx context.Context) (<-chan Event, error) {
	eventsMap := f.collection.Maps["cc01_xdp_events"]
	if eventsMap == nil {
		return nil, errors.New("xdp: events map topilmadi")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("xdp: hodisalarni o'qish: %w", err)
	}

	out := make(chan Event, 128)

	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	go func() {
		defer close(out)
		defer reader.Close()

		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
					return
				}
				f.log.Warn("hodisani o'qish", "err", err)
				continue
			}

			event, err := decodeEvent(record.RawSample)
			if err != nil {
				f.log.Warn("hodisani o'qib bo'lmadi", "err", err)
				continue
			}

			select {
			case out <- event:
			case <-ctx.Done():
				return
			default:
				// Iste'molchi ulgurmayapti. Bloklansak, ring buffer
				// to'lib yadro tomonda YANA KO'PROQ hodisa
				// yo'qolardi.
				f.log.Debug("hodisa tashlandi: iste'molchi ulgurmayapti")
			}
		}
	}()

	return out, nil
}

func decodeEvent(raw []byte) (Event, error) {
	if len(raw) < eventSize {
		return Event{}, fmt.Errorf("xdp: hodisa qisqa: %d bayt, %d kutilgan",
			len(raw), eventSize)
	}

	src, ok := netip.AddrFromSlice(raw[8:24])
	if !ok {
		return Event{}, errors.New("xdp: manba manzili yaroqsiz")
	}

	return Event{
		Uptime: time.Duration(binary.LittleEndian.Uint64(raw[0:8])),
		Src:    src,
		Stage:  Stage(raw[24]),
		DryRun: raw[25] != 0,
	}, nil
}
