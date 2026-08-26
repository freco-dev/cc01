package tcpolicy

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

// Event — tashlangan paket haqidagi xabar.
//
// Hisoblagichlar "nechta" ni aytadi, hodisa esa "qaysi manzil, qaysi
// qoida, qaysi port" ni. Nosozlikni tekshirishda aynan shu kerak:
// "deny-by-default hamma narsani tashlayapti" xabari foydasiz,
// "node X 5432-portga urinyapti va unga qoida yo'q" esa harakatga
// chorlaydi.
type Event struct {
	// Uptime — yadro monotonik soati bo'yicha vaqt.
	//
	// Devor soati EMAS: XDP/tc ichida uni o'qish qimmat va u
	// sakrashi mumkin. Chaqiruvchi kerak bo'lsa uni o'z soatiga
	// moslaydi.
	Uptime time.Duration

	Src netip.Addr
	Dst netip.Addr

	// Port — maqsad porti. 0 — protokolda port yo'q yoki
	// sarlavha o'qilmadi.
	Port uint16

	// Proto — IP protokol raqami (6=TCP, 17=UDP, 58=ICMPv6).
	Proto uint8

	// Identity — manba tushgan guruh. 0 — noma'lum manba.
	Identity uint32

	// RuleID — qaysi qoida ishladi. 0 — qoida umuman topilmadi
	// (deny-by-default).
	RuleID uint32

	// DryRun — hukm qo'llandimi yoki faqat hisoblandimi.
	DryRun bool
}

// eventSize — `struct cc01_event` ning o'lchami.
const eventSize = 56

// String hodisani o'qiladigan ko'rinishga keltiradi.
func (e Event) String() string {
	action := "tashlandi"
	if e.DryRun {
		action = "tashlangan bo'lardi"
	}

	reason := fmt.Sprintf("qoida %d", e.RuleID)
	if e.RuleID == 0 {
		reason = "qoida yo'q"
	}

	return fmt.Sprintf("%s → %s port=%d proto=%d identity=%d: %s (%s)",
		e.Src, e.Dst, e.Port, e.Proto, e.Identity, action, reason)
}

// Events hodisalarni o'qish uchun kanal ochadi.
//
// Kanal ctx bekor qilinganda yoki filtr yopilganda yopiladi.
//
// ⚠️ O'qishni kechiktirmang: ring buffer to'lsa yadro yangi
// hodisalarni TASHLAYDI (`StatEventLost` oshadi). Bu ataylab —
// kuzatuv hech qachon filtrlashdan muhimroq emas.
func (f *Filter) Events(ctx context.Context) (<-chan Event, error) {
	eventsMap := f.collection.Maps["cc01_events"]
	if eventsMap == nil {
		return nil, errors.New("tcpolicy: events map topilmadi")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("tcpolicy: hodisalarni o'qish: %w", err)
	}

	out := make(chan Event, 128)

	// Reader'ni ctx bekor qilinganda yopamiz — u bloklangan
	// `Read` ni uyg'otadigan yagona yo'l.
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
				// Iste'molchi ulgurmayapti. Hodisani tashlaymiz —
				// bu yerda bloklansak, ring buffer to'lib, yadro
				// tomonda YANA KO'PROQ hodisa yo'qolardi.
				f.log.Debug("hodisa tashlandi: iste'molchi ulgurmayapti")
			}
		}
	}()

	return out, nil
}

// decodeEvent yadro yozgan baytlarni o'qiydi.
//
// ⚠️ Tartib va siljishlar `struct cc01_event` bilan aynan mos
// kelishi shart.
func decodeEvent(raw []byte) (Event, error) {
	if len(raw) < eventSize {
		return Event{}, fmt.Errorf("tcpolicy: hodisa qisqa: %d bayt, %d kutilgan",
			len(raw), eventSize)
	}

	src, ok := netip.AddrFromSlice(raw[8:24])
	if !ok {
		return Event{}, errors.New("tcpolicy: manba manzili yaroqsiz")
	}
	dst, ok := netip.AddrFromSlice(raw[24:40])
	if !ok {
		return Event{}, errors.New("tcpolicy: maqsad manzili yaroqsiz")
	}

	return Event{
		Uptime:   time.Duration(binary.LittleEndian.Uint64(raw[0:8])),
		Src:      src,
		Dst:      dst,
		Port:     binary.LittleEndian.Uint16(raw[40:42]),
		Proto:    raw[42],
		Identity: binary.LittleEndian.Uint32(raw[44:48]),
		RuleID:   binary.LittleEndian.Uint32(raw[48:52]),
		DryRun:   raw[52] != 0,
	}, nil
}
