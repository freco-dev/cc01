// Package cluster Control Plane holatini Raft bilan replikatsiya
// qiladi (ARCHITECTURE.md §3.1.6, ADR-006).
package cluster

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/freco-dev/cc01/control/ipam"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"github.com/hashicorp/raft"
	"google.golang.org/protobuf/proto"
)

// FSM — Raft jurnalini IPAM holatiga qo'llaydigan holat mashinasi.
//
// Raft `Apply` ni QAT'IY KETMA-KET chaqiradi, ya'ni ichida qulf
// kerak emas. Lekin `View` va `Snapshot` boshqa goroutine'lardan
// keladi, shuning uchun qulf baribir bor.
type FSM struct {
	mu    sync.RWMutex
	state *ipam.State
	log   *slog.Logger
}

func NewFSM(logger *slog.Logger) *FSM {
	if logger == nil {
		logger = slog.Default()
	}
	return &FSM{state: ipam.NewState(), log: logger}
}

// applyResult — Apply qaytaradigan natija.
//
// Raft `Apply` ning qaytargan qiymatini `ApplyFuture.Response()`
// orqali AYNAN liderga qaytaradi; boshqa replikalarda u tashlab
// yuboriladi. Shuning uchun xatoni shu yerda qaytarish xavfsiz —
// u holatga ta'sir qilmaydi.
type applyResult struct {
	lease     *ipam.Lease
	reclaimed int
	err       error
}

// Apply bitta jurnal yozuvini qo'llaydi.
func (f *FSM) Apply(entry *raft.Log) any {
	cmd := &cc01v1.LeaseCommand{}
	if err := proto.Unmarshal(entry.Data, cmd); err != nil {
		// Jurnaldagi yozuvni o'qib bo'lmasa — bu jiddiy nosozlik.
		// Lekin panic qilib bo'lmaydi: o'sha yozuv HAMMA replikada
		// bir xil, ya'ni butun klaster o'lardi. O'tkazib yuboramiz
		// va bu ham deterministik.
		f.log.Error("jurnal yozuvi o'qilmadi", "index", entry.Index, "err", err)
		return applyResult{err: fmt.Errorf("cluster: yozuv %d: %w", entry.Index, err)}
	}

	f.mu.Lock()
	lease, reclaimed, err := f.state.Apply(cmd)
	f.mu.Unlock()

	return applyResult{lease: lease, reclaimed: reclaimed, err: err}
}

// View holatni faqat o'qish uchun beradi.
func (f *FSM) View(fn func(*ipam.State) error) error {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return fn(f.state)
}

// Snapshot holatning nusxasini oladi.
//
// Nusxa qulf ostida olinadi va keyin qulfsiz yoziladi: yozish diskka
// tegadi va uni qulf ostida qilish butun klasterni to'xtatib
// qo'yardi.
func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	leases := make([]*ipam.Lease, 0, len(f.state.Leases))
	for _, lease := range f.state.Leases {
		leases = append(leases, lease.Clone())
	}

	return &snapshot{leases: leases}, nil
}

// Restore snapshot'dan holatni tiklaydi.
//
// Raft buni Apply bilan bir vaqtda chaqirmaydi, lekin View bilan
// chaqirishi mumkin — shuning uchun qulf ostida.
func (f *FSM) Restore(reader io.ReadCloser) error {
	defer reader.Close()

	leases, err := readSnapshot(reader)
	if err != nil {
		return err
	}

	state := ipam.NewState()
	for _, lease := range leases {
		state.Insert(lease)
	}

	f.mu.Lock()
	f.state = state
	f.mu.Unlock()

	f.log.Info("holat snapshot'dan tiklandi", "leases", len(leases))
	return nil
}

// snapshot — yozishga tayyor holat nusxasi.
type snapshot struct{ leases []*ipam.Lease }

// Persist snapshot'ni yozadi.
//
// Format: har bir ijara uchun 4 baytlik uzunlik + protobuf. Oddiy
// uzunlik-prefiksi yetarli, chunki faylni faqat biz o'qiymiz va
// yozuvlar ketma-ket keladi.
func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	err := func() error {
		var header [4]byte

		for _, lease := range s.leases {
			encoded, err := proto.Marshal(leaseToProto(lease))
			if err != nil {
				return fmt.Errorf("cluster: ijarani kodlash: %w", err)
			}

			binary.BigEndian.PutUint32(header[:], uint32(len(encoded)))
			if _, err := sink.Write(header[:]); err != nil {
				return err
			}
			if _, err := sink.Write(encoded); err != nil {
				return err
			}
		}
		return nil
	}()

	if err != nil {
		// Cancel yozilganini bekor qiladi — yarim snapshot qolsa
		// keyingi tiklash buzilgan holatni o'qirdi.
		_ = sink.Cancel()
		return err
	}

	return sink.Close()
}

func (s *snapshot) Release() {}

// readSnapshot Persist yozgan formatni o'qiydi.
func readSnapshot(reader io.Reader) ([]*ipam.Lease, error) {
	var (
		header [4]byte
		leases []*ipam.Lease
	)

	for {
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return leases, nil
			}
			return nil, fmt.Errorf("cluster: snapshot sarlavhasi: %w", err)
		}

		size := binary.BigEndian.Uint32(header[:])
		if size > maxLeaseSize {
			return nil, fmt.Errorf("cluster: snapshot yozuvi juda katta: %d", size)
		}

		buf := make([]byte, size)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, fmt.Errorf("cluster: snapshot yozuvi: %w", err)
		}

		encoded := &cc01v1.LeaseRecord{}
		if err := proto.Unmarshal(buf, encoded); err != nil {
			return nil, fmt.Errorf("cluster: snapshot yozuvini o'qish: %w", err)
		}

		lease, err := leaseFromProto(encoded)
		if err != nil {
			return nil, err
		}
		leases = append(leases, lease)
	}
}

// maxLeaseSize — bitta snapshot yozuvining chegarasi.
//
// Buzilgan faylda uzunlik maydoni ixtiyoriy son bo'lishi mumkin va
// usiz biz o'sha sonda bayt ajratishga urinardik.
const maxLeaseSize = 1 << 20
