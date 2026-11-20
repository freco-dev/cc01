package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/freco-dev/cc01/core-server/access"
	"github.com/freco-dev/cc01/core-server/config"
	"github.com/freco-dev/cc01/core-server/usage"
)

// usageFlushTimeout — to'xtashda (Stop) navbatni AP'ga yuborish uchun
// umumiy muddat (best-effort; har RPC o'z taymauti bilan).
const usageFlushTimeout = 5 * time.Second

// maxTunnelIDLen — tunnel ID uzunligi chegarasi (AP ustuni).
const maxTunnelIDLen = 128

// initUsage foydalanish hisobotini sozlaydi (DEV_SPEC §8). Faqat
// authorizer access.UsageReporter bo'lsa (AllowAll — yo'q) va
// CC01_USAGE_INTERVAL > 0 bo'lsa yoqiladi; aks holda j.usage nil qoladi
// va tunnellar o'lchanmaydi (hisoblagichlar baribir ishlaydi).
func (j *CC01Server) initUsage() {
	reporter, ok := j.authorizer.(access.UsageReporter)
	if !ok || j.config.UsageInterval <= 0 {
		if j.config.AuthMode != config.AuthDisabled {
			log.Printf("⚠️  foydalanish hisoboti O'CHIQ (CC01_USAGE_INTERVAL=0): " +
				"AP'ga trafik va tunnel-soatlar yuborilmaydi")
		}
		return
	}
	j.usage = usage.New(usage.Options{
		Reporter: reporter,
		Interval: j.config.UsageInterval,
		Logf:     j.logf,
	})
	log.Printf("[usage] har %s da oyna kesiladi va AP'ga yuboriladi "+
		"(navbat ≤ %d oyna, xotirada — edge qayta ishga tushsa yo'qoladi)",
		j.config.UsageInterval, usage.DefaultQueueMax)
}

// newTunnelID — tunnel NUSXASI uchun noyob ID: "<host>:<port>/<16 hex>".
//
// AP foydalanish oynalarini (tunnel_id, window_start) bo'yicha idempotent
// saqlaydi: xuddi shu nom bilan qayta ochilgan tunnel eski ID'ni olsa,
// uning oynalari avvalgisiniki bilan to'qnashib, dublikat sifatida
// tashlanardi. Shuning uchun har ochilishda 8 tasodifiy bayt qo'shiladi.
// ID ≤ 128 belgi: juda uzun host qismi qisqartiriladi (noyoblikni
// tasodifiy qism ta'minlaydi).
func newTunnelID(host string, port uint16) string {
	var suffix [8]byte
	_, _ = rand.Read(suffix[:]) // crypto/rand.Read xato qaytarmaydi
	tail := "/" + hex.EncodeToString(suffix[:])

	base := fmt.Sprintf("%s:%d", host, port)
	if limit := maxTunnelIDLen - len(tail); len(base) > limit {
		base = base[:limit]
	}
	return base + tail
}
