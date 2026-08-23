package engine

import (
	"time"

	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/path"
	"github.com/freco-dev/cc01/daemon/router"
)

const (
	// KeepaliveInterval — NAT jadvali TTL'idan (odatda 30 s) kichik
	// bo'lishi shart, aks holda NAT yozuvi eskirib, kirish paketlari
	// yo'qoladi (ARCHITECTURE.md §6.3).
	KeepaliveInterval = 25 * time.Second

	// tickInterval — taymerlarni tekshirish davri.
	//
	// Yo'l uzilishini tez aniqlash uchun u FastProbeInterval dan
	// katta bo'lmasligi kerak (ARCHITECTURE.md §6.3: 250 ms).
	tickInterval = path.FastProbeInterval
)

// runTimers davriy ishlarni bajaradi: rekey, keepalive, eskirgan
// sessiyalarni tozalash.
func (e *Engine) runTimers() {
	defer e.wg.Done()

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	lastKeepalive := make(map[noise.PublicKey]time.Time)

	for {
		select {
		case <-e.closed:
			return

		case now := <-ticker.C:
			// Yo'llarni o'lchaymiz — bu ADR-005 dagi "P2P-upgrade"
			// qismi: relay ishlab turgan holda to'g'ridan-to'g'ri
			// yo'l fon rejimida sinaladi.
			e.probePeers(now)

			// Ketgan peerlarning holati va soketlari tozalanadi.
			e.reapOrphans()

			for _, peer := range e.router.Peers() {
				e.tickPeer(peer, now, lastKeepalive)

				// Oddiy probe'lar uzoq vaqt natija bermasa,
				// sabab katta ehtimol symmetric NAT — teshik
				// ochishga o'tamiz.
				e.maybePunch(peer, now)
			}
		}
	}
}

func (e *Engine) tickPeer(
	peer *router.Peer,
	now time.Time,
	lastKeepalive map[noise.PublicKey]time.Time,
) {
	session := peer.Session()
	if session == nil {
		return
	}

	if session.Expired() {
		e.log.Debug("sessiya eskirdi", "peer", peer.PublicKey)
		peer.ClearSession()
		e.router.UnbindSession(session.LocalIndex())
		return
	}

	// Rekey'ni FAQAT initiator boshlaydi. Ikkala tomon bir vaqtda
	// boshlasa ikkita sessiya paydo bo'lib, "thundering herd" hosil
	// qiladi (ARCHITECTURE.md §3.5).
	if session.NeedsRekey() && session.IsInitiator() {
		e.log.Debug("rekey boshlanmoqda", "peer", peer.PublicKey, "age", session.Age())
		e.beginHandshake(peer)
	}

	if now.Sub(lastKeepalive[peer.PublicKey]) < KeepaliveInterval {
		return
	}
	lastKeepalive[peer.PublicKey] = now

	packet, err := session.Seal(noise.TypeKeepalive, nil)
	if err != nil {
		return
	}
	if err := e.sendVia(peer, packet); err != nil {
		e.log.Debug("keepalive yuborilmadi", "peer", peer.PublicKey, "err", err)
	}
}
