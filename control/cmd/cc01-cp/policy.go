package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/freco-dev/cc01/control/policy"
)

// reloadPolicy ACL faylini qayta o'qiydi va qo'llaydi.
func reloadPolicy(store *policy.Store, path string, logger *slog.Logger) error {
	rules, err := policy.LoadFile(path)
	if err != nil {
		return err
	}

	version := store.Set(rules)
	logger.Info("policy yuklandi", "file", path, "rules", len(rules), "version", version)
	return nil
}

// watchPolicyReloads SIGHUP kelganda ACL ni qayta o'qiydi.
//
// Fayl kuzatuvchisi (inotify) EMAS: tahrirlash paytida fayl bir
// necha marta yozilishi mumkin va yarim yozilgan ACL ni qo'llash
// butun trafikni kesib qo'yardi. SIGHUP esa operator "tayyor"
// deganini bildiradi.
func watchPolicyReloads(store *policy.Store, path string, logger *slog.Logger) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)

	for range signals {
		if err := reloadPolicy(store, path, logger); err != nil {
			// Qayta yuklashdagi xato halokatli EMAS: eski
			// qoidalar amalda qoladi. Yaroqsiz fayl tufayli
			// ishlab turgan policy'ni yo'qotish xavfliroq.
			logger.Error("policy qayta yuklanmadi, eski qoidalar qoladi",
				"file", path, "err", err)
		}
	}
}
