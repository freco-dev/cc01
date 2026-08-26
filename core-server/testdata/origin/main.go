// Tunnel ortidagi lokal xizmat — demo uchun.
//
// Alohida binar: konteynerda `python3`/`nc` bo'lishiga tayanish
// demo'ni bazaviy image tarkibiga bog'lab qo'yardi.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {
	listen := flag.String("listen", ":8080", "tinglash manzili")
	body := flag.String("body", "salom cc01 tunnelidan", "javob matni")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Host sarlavhasi ham qaytariladi: tunnel qaysi nom bilan
		// kelganini demoda ko'rsatish uchun.
		fmt.Fprintf(w, "%s (host=%s)\n", *body, r.Host)
	})

	log.Printf("origin tinglayapti: %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
