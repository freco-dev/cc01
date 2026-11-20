package tunnel

import (
	"io"
	"net"
	"sync/atomic"
)

// Usage — tunnel ochilgandan beri yig'ilgan hisoblagichlar (kumulyativ,
// faqat o'sadi). Oyna (window) bo'yicha farqni usage paketi hisoblaydi:
// ketma-ket ikki o'qish orasidagi ayirma.
type Usage struct {
	// BytesIn — ommaviy tomondan tunnelga (internet → lokal xizmat)
	// yetkazilgan baytlar, HTTP'da Host'ni aniqlash uchun oldindan
	// o'qilgan bufer ham shu jumladan. TLS'dan keyingi (ochiq) baytlar.
	BytesIn uint64
	// BytesOut — xususiy tomondan ommaviy klientga qaytgan baytlar.
	BytesOut uint64
	// Connections — qabul qilingan (navbatga qo'yilgan, so'ng
	// ko'priklangan) ommaviy ulanishlar.
	Connections uint64
	// Rejected — max_conns limiti tufayli rad etilgan ommaviy ulanishlar
	// (klientga ConnectionReceived{rate_limited} ketadi).
	Rejected uint64
}

// usageCounters — tunnelning hisoblagichlari. Faqat atomiklar: issiq
// yo'lda (Bind) qulf yo'q.
type usageCounters struct {
	bytesIn     atomic.Uint64
	bytesOut    atomic.Uint64
	connections atomic.Uint64
	rejected    atomic.Uint64
}

// Usage hisoblagichlarning joriy qiymatini qaytaradi. Har maydon alohida
// atomik o'qiladi: maydonlar orasidagi kelishuv kerak emas — keyingi
// o'qishda kechikkan qiymat albatta ko'rinadi, hech narsa yo'qolmaydi.
func (t *tunnel) Usage() Usage {
	return Usage{
		BytesIn:     t.usage.bytesIn.Load(),
		BytesOut:    t.usage.bytesOut.Load(),
		Connections: t.usage.connections.Load(),
		Rejected:    t.usage.rejected.Load(),
	}
}

// bindCounted src'dan dst'ga nusxalaydi va dst'ga HAQIQATAN yozilgan
// baytlarni counter'ga qo'shadi (yozish xatosida ham yozilgan qism
// hisoblanadi). Hisoblash nusxa ko'chirish goroutine'ida, atomik bilan.
func bindCounted(src, dst net.Conn, counter *atomic.Uint64, debug io.Writer) error {
	defer src.Close()
	defer dst.Close()
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			if written > 0 && counter != nil {
				counter.Add(uint64(written))
			}
			if writeErr != nil {
				return writeErr
			}
			if debug != nil {
				_, _ = debug.Write(buf[:n])
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}
