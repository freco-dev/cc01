package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/freco-dev/cc01/control/ipam"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"google.golang.org/protobuf/proto"
)

// ErrNotLeader — yozuv liderga yuborilishi kerak.
//
// Xato liderning manzilini ham olib yuradi, shunda chaqiruvchi
// so'rovni qayta yo'naltira oladi.
type ErrNotLeader struct {
	// Leader — hozirgi lider manzili; bo'sh bo'lsa lider hali
	// tanlanmagan.
	Leader string
}

func (e *ErrNotLeader) Error() string {
	if e.Leader == "" {
		return "cluster: bu node lider emas, lider hali tanlanmagan"
	}
	return fmt.Sprintf("cluster: bu node lider emas, lider: %s", e.Leader)
}

// Config — klaster node'ining sozlamalari.
type Config struct {
	// ID — klasterdagi noyob identifikator.
	ID string

	// Bind — Raft transporti tinglaydigan manzil (host:port).
	Bind string

	// Advertise — boshqa nodelarga ko'rinadigan manzil. Bo'sh bo'lsa
	// Bind ishlatiladi.
	//
	// Ular farq qilishi mumkin: konteynerda Bind ko'pincha
	// `0.0.0.0:port`, e'lon qilinadigan manzil esa haqiqiy IP.
	Advertise string

	// Dir — jurnal, barqaror holat va snapshot'lar papkasi.
	Dir string

	// Bootstrap — klasterni SHU node bilan boshlash.
	//
	// Faqat BIRINCHI marta va faqat BITTA nodeda: ikkita node
	// bir vaqtda bootstrap qilsa, ikkita alohida klaster paydo
	// bo'ladi va ular hech qachon birlashmaydi.
	Bootstrap bool

	// Peers — bootstrap paytidagi boshlang'ich a'zolar
	// (ID va manzil). Bo'sh bo'lsa faqat o'zi.
	Peers []Peer

	Logger *slog.Logger
}

// Peer — klaster a'zosi.
type Peer struct {
	ID      string
	Address string
}

// Node — Raft bilan replikatsiya qilinadigan Control Plane holati.
type Node struct {
	raft      *raft.Raft
	fsm       *FSM
	transport *raft.NetworkTransport
	stable    *raftboltdb.BoltStore
	log       *slog.Logger
	cfg       Config

	// done — watchLeadership'ni to'xtatish uchun.
	done      chan struct{}
	closeOnce sync.Once
}

// applyTimeout — buyruqning quorum tomonidan tasdiqlanishini kutish
// muddati.
//
// Lider yo'qolsa `Apply` javob bermay qoladi; cheklovsiz chaqiruvchi
// abadiy osilib qolardi. Failover odatda bir necha soniya oladi,
// shuning uchun undan kattaroq qiymat olingan.
const applyTimeout = 10 * time.Second

// Start Raft node'ini ko'taradi.
func Start(cfg Config) (*Node, error) {
	if cfg.ID == "" {
		return nil, errors.New("cluster: node ID berilmagan")
	}
	if cfg.Dir == "" {
		return nil, errors.New("cluster: papka berilmagan")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("cluster: papka yaratish: %w", err)
	}

	advertise := cfg.Advertise
	if advertise == "" {
		advertise = cfg.Bind
	}

	addr, err := net.ResolveTCPAddr("tcp", advertise)
	if err != nil {
		return nil, fmt.Errorf("cluster: e'lon manzili (%s): %w", advertise, err)
	}

	// Transport va snapshot ombori ham o'z loglarini yozadi. Ularni
	// stderr'ga qoldirsak, ular boshqa formatda chiqib qolgan loglar
	// bilan aralashib ketardi.
	raftLogs := &slogWriter{log: cfg.Logger.With("component", "raft")}

	transport, err := raft.NewTCPTransport(cfg.Bind, addr, 3, 10*time.Second, raftLogs)
	if err != nil {
		return nil, fmt.Errorf("cluster: transport (%s): %w", cfg.Bind, err)
	}

	// Jurnal va barqaror holat bitta BoltDB faylida. Ular birga
	// yozilishi kerak: jurnal yozuvi saqlanib, unga mos `currentTerm`
	// yo'qolsa Raft o'z kafolatlarini buzardi.
	stable, err := raftboltdb.NewBoltStore(filepath.Join(cfg.Dir, "raft.db"))
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("cluster: jurnal: %w", err)
	}

	// Uchta snapshot saqlanadi: eskisi buzilgan bo'lsa oldingisiga
	// qaytish imkoni qoladi.
	snapshots, err := raft.NewFileSnapshotStore(cfg.Dir, 3, raftLogs)
	if err != nil {
		_ = stable.Close()
		_ = transport.Close()
		return nil, fmt.Errorf("cluster: snapshot ombori: %w", err)
	}

	fsm := NewFSM(cfg.Logger)

	raftCfg := raft.DefaultConfig()
	raftCfg.LocalID = raft.ServerID(cfg.ID)
	raftCfg.Logger = hclogAdapter(cfg.Logger)

	// DoD: lider yo'qolganda yangisi 5 soniyadan tez tanlanishi kerak
	// (DEV_SPEC §8). Standart qiymatlar bunga yetmaydi.
	raftCfg.HeartbeatTimeout = 500 * time.Millisecond
	raftCfg.ElectionTimeout = 500 * time.Millisecond
	raftCfg.LeaderLeaseTimeout = 250 * time.Millisecond
	raftCfg.CommitTimeout = 50 * time.Millisecond

	node, err := raft.NewRaft(raftCfg, fsm, stable, stable, snapshots, transport)
	if err != nil {
		_ = stable.Close()
		_ = transport.Close()
		return nil, fmt.Errorf("cluster: raft: %w", err)
	}

	if cfg.Bootstrap {
		if err := bootstrap(node, cfg, transport, stable, snapshots); err != nil {
			return nil, err
		}
	}

	cfg.Logger.Info("klaster node'i ishga tushdi",
		"id", cfg.ID, "bind", cfg.Bind, "advertise", advertise,
		"bootstrap", cfg.Bootstrap)

	n := &Node{
		raft: node, fsm: fsm, transport: transport,
		stable: stable, log: cfg.Logger, cfg: cfg,
		done: make(chan struct{}),
	}

	go n.watchLeadership()

	return n, nil
}

// watchLeadership liderlik o'zgarishini logga yozadi.
//
// Bu operator uchun eng muhim hodisa: klaster nosoz bo'lsa, birinchi
// savol "lider kim va u qachon almashdi" bo'ladi. Raft o'zi buni
// yozadi, lekin Debug darajasida va boshqa yuzlab xabarlar orasida.
func (n *Node) watchLeadership() {
	for {
		select {
		case <-n.done:
			return

		case leader, ok := <-n.raft.LeaderCh():
			if !ok {
				return
			}
			if leader {
				n.log.Info("BU NODE LIDER BO'LDI", "id", n.cfg.ID)
			} else {
				n.log.Info("liderlik yo'qotildi", "id", n.cfg.ID, "yangi_lider", n.Leader())
			}
		}
	}
}

// bootstrap klasterni boshlang'ich a'zolar bilan yaratadi.
//
// Allaqachon holat bo'lsa hech narsa qilinmaydi: qayta ishga
// tushirilgan node bootstrap qilmasligi kerak, aks holda u
// klasterning tarixini o'chirib yuborardi.
func bootstrap(
	node *raft.Raft,
	cfg Config,
	transport raft.Transport,
	stable *raftboltdb.BoltStore,
	snapshots raft.SnapshotStore,
) error {
	// Jurnal allaqachon bo'lsa bootstrap qilmaymiz: qayta ishga
	// tushirilgan node klasterning tarixini o'chirib yuborardi.
	hasState, err := raft.HasExistingState(stable, stable, snapshots)
	if err != nil {
		return fmt.Errorf("cluster: mavjud holatni tekshirish: %w", err)
	}
	if hasState {
		cfg.Logger.Info("mavjud jurnal topildi, bootstrap o'tkazib yuborildi", "id", cfg.ID)
		return nil
	}

	servers := []raft.Server{{
		ID:      raft.ServerID(cfg.ID),
		Address: transport.LocalAddr(),
	}}

	for _, peer := range cfg.Peers {
		if peer.ID == cfg.ID {
			continue
		}
		servers = append(servers, raft.Server{
			ID:      raft.ServerID(peer.ID),
			Address: raft.ServerAddress(peer.Address),
		})
	}

	future := node.BootstrapCluster(raft.Configuration{Servers: servers})
	if err := future.Error(); err != nil && !errors.Is(err, raft.ErrCantBootstrap) {
		return fmt.Errorf("cluster: bootstrap: %w", err)
	}
	return nil
}

// Propose buyruqni jurnalga yozadi va qo'llanishini kutadi.
//
// Faqat LIDER bajara oladi. Boshqa nodelar ErrNotLeader qaytaradi —
// chaqiruvchi so'rovni liderga yo'naltirishi kerak.
func (n *Node) Propose(
	ctx context.Context,
	cmd *cc01v1.LeaseCommand,
) (*ipam.Lease, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}

	if n.raft.State() != raft.Leader {
		return nil, 0, &ErrNotLeader{Leader: string(n.raft.Leader())}
	}

	encoded, err := proto.Marshal(cmd)
	if err != nil {
		return nil, 0, fmt.Errorf("cluster: buyruqni kodlash: %w", err)
	}

	future := n.raft.Apply(encoded, applyTimeout)
	if err := future.Error(); err != nil {
		// Lider almashgan bo'lishi mumkin — buni alohida ajratamiz,
		// shunda chaqiruvchi qayta yo'naltira oladi.
		if errors.Is(err, raft.ErrLeadershipLost) || errors.Is(err, raft.ErrNotLeader) {
			return nil, 0, &ErrNotLeader{Leader: string(n.raft.Leader())}
		}
		return nil, 0, fmt.Errorf("cluster: buyruqni qo'llash: %w", err)
	}

	result, ok := future.Response().(applyResult)
	if !ok {
		return nil, 0, errors.New("cluster: kutilmagan javob turi")
	}

	return result.lease, result.reclaimed, result.err
}

// View holatni faqat o'qish uchun beradi.
//
// ⚠️ O'qish MAHALLIY: bu node ortda qolgan bo'lsa eski holat
// ko'rinishi mumkin. Kuchli o'qish uchun `raft.Barrier` kerak va u
// har bir o'qishga quorum aylanishi qo'shadi. NetworkMap uchun bir
// necha yuz millisekundlik kechikish muammo emas — nodelar baribir
// stream orqali yangilanadi.
func (n *Node) View(ctx context.Context, fn func(*ipam.State) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return n.fsm.View(fn)
}

// Barrier jurnaldagi hamma tasdiqlangan yozuv FSM ga qo'llanishini
// kutadi.
//
// Nega kerak: `View` MAHALLIY o'qiydi, replikatsiya esa asinxron.
// Yangi tanlangan lider hamma tasdiqlangan yozuvni JURNALIDA
// saqlaydi, lekin ularni FSM ga qo'llash biroz vaqt oladi — shu
// oraliqda o'qish eski holatni ko'rsatadi.
//
// Bu taqsimlashning to'g'riligiga ta'sir qilmaydi: buyruq jurnalga
// tushgach, u eski yozuvlardan KEYIN qo'llanadi va `State.Apply`
// prefiksni yangilangan holat bo'yicha qayta tekshiradi. Barrier
// esa "o'z yozganingni o'qish" kerak bo'lgan joylar uchun.
func (n *Node) Barrier(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	future := n.raft.Barrier(applyTimeout)
	if err := future.Error(); err != nil {
		return fmt.Errorf("cluster: barrier: %w", err)
	}
	return nil
}

// IsLeader — shu node lidermi.
func (n *Node) IsLeader() bool { return n.raft.State() == raft.Leader }

// Leader — hozirgi lider manzili; bo'sh bo'lsa tanlanmagan.
func (n *Node) Leader() string { return string(n.raft.Leader()) }

// LeaderChanges — lider almashganda signal beradigan kanal.
func (n *Node) LeaderChanges() <-chan bool { return n.raft.LeaderCh() }

// AddPeer klasterga yangi a'zo qo'shadi (faqat lider).
func (n *Node) AddPeer(id, address string) error {
	future := n.raft.AddVoter(raft.ServerID(id), raft.ServerAddress(address), 0, applyTimeout)
	return future.Error()
}

// Close node'ni to'xtatadi.
func (n *Node) Close() error {
	n.closeOnce.Do(func() { close(n.done) })

	// Lidership'ni ixtiyoriy ravishda topshiramiz: shunda klaster
	// election timeout'ni kutmasdan yangi lider tanlaydi.
	if n.raft.State() == raft.Leader {
		if err := n.raft.LeadershipTransfer().Error(); err != nil {
			n.log.Debug("liderlikni topshirib bo'lmadi", "err", err)
		}
	}

	shutdown := n.raft.Shutdown()

	return errors.Join(
		shutdown.Error(),
		n.transport.Close(),
		n.stable.Close(),
	)
}

// Node IPAM ning Store interfeysini qanoatlantiradi — allokator
// xotiradagi va klasterdagi holat orasida farq ko'rmaydi.
//
// Bu tekshiruv kompilyatsiya vaqtida: interfeys o'zgarsa, xato
// birinchi ishga tushirishda emas, build'da chiqadi.
var _ ipam.Store = (*Node)(nil)
