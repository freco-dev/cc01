package ipc

import "runtime"

// maxSocketPath — UNIX soketi yo'lining eng katta uzunligi.
//
// Yadro uni `sockaddr_un.sun_path` massiviga nusxalaydi va u qat'iy
// o'lchamda: Linux'da 108 bayt, BSD/macOS'da 104. Oxirgi bayt nol
// tugatuvchi uchun ketadi.
var maxSocketPath = func() int {
	if runtime.GOOS == "linux" {
		return 107
	}
	return 103
}()
