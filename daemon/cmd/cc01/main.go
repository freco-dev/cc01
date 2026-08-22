// cc01 — mesh'ni boshqarish va kuzatish uchun buyruq qatori
// (DEV_SPEC §5.1).
//
// Hozircha faqat o'qish buyruqlari: `status`, `peer list`, `doctor`.
// `up`/`down` demon hayot siklini boshqarishni talab qiladi va
// keyingi qadamda qo'shiladi.
package main

import (
	"fmt"
	"os"
)

const version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// Buyruq nomidan keyingi hamma narsa unga tegishli.
	command, args := os.Args[1], os.Args[2:]

	var err error
	switch command {
	case "status":
		err = runStatus(args)
	case "peer":
		err = runPeer(args)
	case "doctor":
		err = runDoctor(args)
	case "version":
		fmt.Println("cc01", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "cc01: noma'lum buyruq: %s\n\n", command)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "cc01: %v\n", err)
		os.Exit(exitCodeFor(err))
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cc01 — mesh boshqaruvi

Buyruqlar:
  status [--json] [--watch]     demon holati
  peer list [--json] [--online] peerlar va ular bilan qaysi yo'l ishlatilyapti
  doctor                        muhit tekshiruvi
  version

Umumiy bayroqlar:
  --socket <yo'l>               demon soketi (standart: `+DefaultSocketHint+`)

Chiqish kodlari (DEV_SPEC §5.2):
  0   muvaffaqiyat
  2   noto'g'ri parametr
  10  demon ishlamayapti
  11  ruxsat yo'q
`)
}
