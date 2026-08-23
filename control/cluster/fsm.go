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

	// identities — node_id → sertifikat pini.
	//
	// IPAM holatidan alohida: bu manzil taqsimlash emas, kimligini
	// tasdiqlash masalasi. Bitta FSM ikkalasini ham replikatsiya
	// qiladi, chunki ular bir xil jurnal va bir xil snapshot orqali
	// ketishi kerak.
	identities map[string]string
}

func NewFSM(logger *slog.Logger) *FSM {
	if logger == nil {
		logger = slog.Default()
	}
	return &FSM{
		state:      ipam.NewState(),
		identities: make(map[string]string),
		log:        logger,
	}
}

// identity bog'langan sertifikatni qaytaradi.
func (f *FSM) identity(nodeID string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	pin, ok := f.identities[nodeID]
	return pin, ok
}

// applyBind bog'lanishni yozadi.
//
// Mavjud bog'lanish JIMGINA almashtirilmaydi: bu node kalitini
// o'g'irlagan tomonga eskisini siqib chiqarish imkonini berardi.
func (f *FSM) applyBind(cmd *cc01v1.BindNodeIdentity) error {
	if cmd.GetNodeId() == "" || cmd.GetCertPin() == "" {
		return errors.New("cluster: bog'lanish buyrug'i to'liq emas")
	}

	if existing, ok := f.identities[cmd.GetNodeId()]; ok && existing != cmd.GetCertPin() {
		return fmt.Errorf("%w: %s", ErrIdentityMismatch, cmd.GetNodeId())
	}

	f.identities[cmd.GetNodeId()] = cmd.GetCertPin()
	return nil
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

	// Bog'lanish buyrug'i IPAM holatiga tegmaydi — uni shu yerda
	// ajratamiz.
	if bind := cmd.GetBind(); bind != nil {
		f.mu.Lock()
		err := f.applyBind(bind)
		f.mu.Unlock()

		return applyResult{err: err}
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

	identities := make(map[string]string, len(f.identities))
	for nodeID, pin := range f.identities {
		identities[nodeID] = pin
	}

	return &snapshot{leases: leases, identities: identities}, nil
}

// Restore snapshot'dan holatni tiklaydi.
//
// Raft buni Apply bilan bir vaqtda chaqirmaydi, lekin View bilan
// chaqirishi mumkin — shuning uchun qulf ostida.
func (f *FSM) Restore(reader io.ReadCloser) error {
	defer reader.Close()

	leases, identities, err := readSnapshot(reader)
	if err != nil {
		return err
	}

	state := ipam.NewState()
	for _, lease := range leases {
		state.Insert(lease)
	}

	f.mu.Lock()
	f.state = state
	f.identities = identities
	f.mu.Unlock()

	f.log.Info("holat snapshot'dan tiklandi",
		"leases", len(leases), "identities", len(identities))
	return nil
}

// snapshot — yozishga tayyor holat nusxasi.
type snapshot struct {
	leases     []*ipam.Lease
	identities map[string]string
}

// Snapshot yozuvining turlari.
//
// Turi baytda yoziladi: snapshot ikki xil yozuvni saqlaydi va ularni
// faqat uzunlik bo'yicha ajratib bo'lmaydi.
const (
	recordLease    byte = 1
	recordIdentity byte = 2
)

// Persist snapshot'ni yozadi.
//
// Format: har bir yozuv uchun 1 bayt turi + 4 bayt uzunlik +
// protobuf. Oddiy ketma-ket format yetarli, chunki faylni faqat biz
// o'qiymiz.
func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	err := func() error {
		for _, lease := range s.leases {
			if err := writeRecord(sink, recordLease, leaseToProto(lease)); err != nil {
				return err
			}
		}

		for nodeID, pin := range s.identities {
			record := &cc01v1.IdentityRecord{NodeId: nodeID, CertPin: pin}
			if err := writeRecord(sink, recordIdentity, record); err != nil {
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

// writeRecord bitta yozuvni turi va uzunligi bilan yozadi.
func writeRecord(sink io.Writer, kind byte, message proto.Message) error {
	encoded, err := proto.Marshal(message)
	if err != nil {
		return fmt.Errorf("cluster: yozuvni kodlash: %w", err)
	}

	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(encoded)))

	if _, err := sink.Write(header[:]); err != nil {
		return err
	}
	_, err = sink.Write(encoded)
	return err
}

// readSnapshot Persist yozgan formatni o'qiydi.
func readSnapshot(reader io.Reader) ([]*ipam.Lease, map[string]string, error) {
	var (
		header     [5]byte
		leases     []*ipam.Lease
		identities = make(map[string]string)
	)

	for {
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return leases, identities, nil
			}
			return nil, nil, fmt.Errorf("cluster: snapshot sarlavhasi: %w", err)
		}

		size := binary.BigEndian.Uint32(header[1:])
		if size > maxLeaseSize {
			return nil, nil, fmt.Errorf("cluster: snapshot yozuvi juda katta: %d", size)
		}

		buf := make([]byte, size)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, nil, fmt.Errorf("cluster: snapshot yozuvi: %w", err)
		}

		switch header[0] {
		case recordLease:
			encoded := &cc01v1.LeaseRecord{}
			if err := proto.Unmarshal(buf, encoded); err != nil {
				return nil, nil, fmt.Errorf("cluster: ijara yozuvi: %w", err)
			}
			lease, err := leaseFromProto(encoded)
			if err != nil {
				return nil, nil, err
			}
			leases = append(leases, lease)

		case recordIdentity:
			encoded := &cc01v1.IdentityRecord{}
			if err := proto.Unmarshal(buf, encoded); err != nil {
				return nil, nil, fmt.Errorf("cluster: bog'lanish yozuvi: %w", err)
			}
			identities[encoded.GetNodeId()] = encoded.GetCertPin()

		default:
			return nil, nil, fmt.Errorf("cluster: snapshot yozuvining turi noma'lum: %d", header[0])
		}
	}
}

// maxLeaseSize — bitta snapshot yozuvining chegarasi.
//
// Buzilgan faylda uzunlik maydoni ixtiyoriy son bo'lishi mumkin va
// usiz biz o'sha sonda bayt ajratishga urinardik.
const maxLeaseSize = 1 << 20
