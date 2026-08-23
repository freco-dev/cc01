package engine

import (
	"time"

	"github.com/freco-dev/cc01/daemon/noise"
	"github.com/freco-dev/cc01/daemon/path"
	"github.com/freco-dev/cc01/daemon/router"
)

// probeTimeout — probe javobsiz deb hisoblanadigan muddat.
//
// FastProbeInterval dan biroz katta: javob kelayotgan bo'lsa uni
// erta "yo'qolgan" deb belgilamaslik kerak.
const probeTimeout = 2 * path.FastProbeInterval

// probePeers har bir peer uchun yo'llarni o'lchaydi.
//
// Bu ADR-005 ning ikkinchi yarmi: ulanish relaydan boshlanadi,
// to'g'ridan-to'g'ri yo'l esa AYNAN SHU YERDA, fon rejimida sinaladi.
func (e *Engine) probePeers(now time.Time) {
	for _, peer := range e.router.Peers() {
		session := peer.Session()
		if session == nil {
			continue
		}

		state := e.pathFor(peer)
		state.expirePending(now, probeTimeout)

		if !state.due(now) {
			continue
		}
		state.scheduleNext(now, state.tracker.ProbeInterval())

		// To'g'ridan-to'g'ri nomzodni sinaymiz. Relay yo'li alohida
		// o'lchanmaydi: u relay klientining keepalive'i orqali tirik
		// ekani bilinadi.
		if endpoint, ok := state.tracker.DirectCandidate(); ok {
			e.sendProbe(peer, session, state, path.KindDirect, endpoint)
		}
	}
}

// sendProbe bitta disco ping yuboradi.
func (e *Engine) sendProbe(
	peer *router.Peer,
	session *noise.Session,
	state *pathState,
	kind path.Kind,
	endpoint netipAddrPort,
) {
	nonce, err := path.NewNonce()
	if err != nil {
		e.log.Debug("probe uchun nonce olinmadi", "peer", peer.PublicKey, "err", err)
		return
	}

	// Bu xato yo'li ilgari jim edi. Yo'l ochilmay qolganda sabab
	// ko'rinmasdi — probe yuborilmagani ham, nima uchun yuborilmagani
	// ham logda qolmasdi.
	packet, err := session.Seal(noise.TypeDisco, path.EncodeDisco(path.Ping, nonce))
	if err != nil {
		e.log.Debug("probe shifrlanmadi", "peer", peer.PublicKey, "kind", kind, "err", err)
		return
	}

	e.log.Debug("probe yuborilmoqda", "peer", peer.PublicKey, "kind", kind, "to", endpoint)

	state.addPending(nonce, kind, e.now())

	if err := e.bind.Send(packet, endpoint); err != nil {
		e.log.Debug("probe yuborilmadi", "peer", peer.PublicKey, "err", err)
	}
}

// handleDisco kelgan ping yoki pongni qayta ishlaydi.
//
// `from` — paket qaysi manzildan kelgani. Relay orqali kelgan bo'lsa u
// yaroqsiz (`relaySentinel`), chunki u holda manba manzili relayniki.
func (e *Engine) handleDisco(
	peer *router.Peer,
	session *noise.Session,
	payload []byte,
	from netipAddrPort,
) {
	kind, nonce, err := path.DecodeDisco(payload)
	if err != nil {
		return
	}

	switch kind {
	case path.Ping:
		// Javob AYNAN o'sha nonce bilan qaytadi — jo'natuvchi shu
		// orqali RTT ni o'lchaydi.
		pong, err := session.Seal(noise.TypeDisco, path.EncodeDisco(path.Pong, nonce))
		if err != nil {
			return
		}

		// Javob AYNAN ping kelgan yo'l bilan qaytadi.
		//
		// Bu — hole punching'ning yuragi. Ikkala tomon bir vaqtda
		// bir-birining public endpointiga yozganda NAT'larda conntrack
		// yozuvlari paydo bo'ladi va to'g'ridan-to'g'ri yo'l ochiladi.
		// Javobni "eng yaxshi" yo'l bilan yuborish bu zanjirni uzardi:
		// relay orqali kelgan pong to'g'ridan-to'g'ri probe'ni
		// tasdiqlamaydi va yo'l abadiy `probing` holatida qolardi.
		if from.IsValid() {
			if err := e.bind.Send(pong, from); err != nil {
				e.log.Debug("pong yuborilmadi", "peer", peer.PublicKey, "to", from, "err", err)
			}
			return
		}

		if err := e.sendViaRelay(peer, pong); err != nil {
			e.log.Debug("pong relay orqali yuborilmadi", "peer", peer.PublicKey, "err", err)
		}

	case path.Pong:
		state := e.pathFor(peer)

		probe, ok := state.takePending(nonce)
		if !ok {
			// Kutilmagan yoki kech kelgan javob.
			return
		}

		rtt := e.now().Sub(probe.sent)
		before := state.tracker.State()
		state.tracker.RecordPong(probe.kind, rtt, e.now())

		if after := state.tracker.State(); after != before {
			e.log.Info("yo'l holati o'zgardi",
				"peer", peer.PublicKey, "from", before, "to", after,
				"rtt", rtt.Round(time.Microsecond))
		}
	}
}

// ─────────────────── pathState yordamchilari ───────────────────

func (s *pathState) due(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.After(s.nextProbe) || s.nextProbe.IsZero()
}

func (s *pathState) scheduleNext(now time.Time, interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextProbe = now.Add(interval)
}

func (s *pathState) addPending(nonce uint64, kind path.Kind, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[nonce] = pendingProbe{kind: kind, sent: now}
}

func (s *pathState) takePending(nonce uint64) (pendingProbe, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	probe, ok := s.pending[nonce]
	if ok {
		delete(s.pending, nonce)
	}
	return probe, ok
}

// expirePending javobsiz qolgan probe'larni yo'qotish deb belgilaydi.
func (s *pathState) expirePending(now time.Time, timeout time.Duration) {
	s.mu.Lock()

	var lost []path.Kind
	for nonce, probe := range s.pending {
		if now.Sub(probe.sent) < timeout {
			continue
		}
		lost = append(lost, probe.kind)
		delete(s.pending, nonce)
	}
	s.mu.Unlock()

	// Qulf tashqarisida: RecordMiss o'z qulfini oladi.
	for _, kind := range lost {
		s.tracker.RecordMiss(kind)
	}
}
