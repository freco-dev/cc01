package cluster

import (
	"bytes"
	"log/slog"

	"github.com/hashicorp/go-hclog"
)

// hclogAdapter Raft ning hclog chiqishini bizning slog'imizga
// yo'naltiradi.
//
// Nega kerak: Raft o'z loglarini hclog orqali chiqaradi va usiz ular
// stderr'ga alohida formatda tushib, qolgan loglar bilan aralashib
// ketardi. Bir joyda va bir formatda bo'lgani nosozlikni tekshirishni
// osonlashtiradi.
//
// Daraja: Raft juda gapiruvchan (har bir heartbeat haqida yozadi),
// shuning uchun hammasi Debug ga tushadi va uni slog filtrlaydi.
// Muhim hodisalar — lider almashuvi, snapshot — baribir bizning
// o'z loglarimizda bor.
func hclogAdapter(logger *slog.Logger) hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Name:        "raft",
		Level:       hclog.Debug,
		Output:      &slogWriter{log: logger.With("component", "raft")},
		DisableTime: true,
	})
}

// slogWriter hclog yozgan qatorlarni slog'ga uzatadi.
type slogWriter struct{ log *slog.Logger }

func (w *slogWriter) Write(p []byte) (int, error) {
	// hclog bir chaqiruvda bitta qator yozadi; oxiridagi nurni
	// olib tashlaymiz, aks holda slog uni xabar ichida saqlab
	// qolardi.
	w.log.Debug(string(bytes.TrimRight(p, "\n")))
	return len(p), nil
}
