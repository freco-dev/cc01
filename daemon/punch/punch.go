// Package punch symmetric NAT ortidagi peer bilan to'g'ridan-to'g'ri
// yo'l ochishga urinadi.
//
// # Muammo
//
// Symmetric NAT har bir CHIQUVCHI OQIM uchun boshqa tashqi port
// beradi. Ya'ni STUN aytgan manzil faqat STUN oqimi uchun to'g'ri:
// peer bizga o'sha manzilga yozsa, NAT'da mos yozuv topilmaydi va
// paket tashlanadi. Oddiy teshik ochish (ikkala tomon bir vaqtda
// bir-birining ma'lum manziliga yozishi) bu yerda ishlamaydi —
// `make relay-demo` shuni ko'rsatadi.
//
// # Yechim: birthday paradoks
//
// Ikkita yarim, ikkalasi ham kerak:
//
//	SEPISH   N ta VAQTINCHALIK soketdan peerning ma'lum manziliga
//	         yozamiz. Har biri NAT'da alohida yozuv ochadi, ya'ni
//	         bizning IP'da N ta tashqi port peerdan paket qabul
//	         qiladigan holatga keladi.
//
//	TAXMIN   peerning IP'sida K ta tasodifiy portga ASOSIY soketdan
//	         yozamiz — u ham sepgan bo'lsa, taxminlarimizdan biri
//	         uning yozuvlaridan biriga tushishi mumkin.
//
// ⚠️ Taxminlar AYNAN asosiy soketdan yuborilishi shart. Peerning
// yozuvi u bizga qaysi manzilga yozgan bo'lsa, faqat o'shandan paket
// qabul qiladi (port-restricted filtrlash) — bu esa bizning ma'lum,
// STUN e'lon qilgan manzilimiz, ya'ni asosiy soket. Vaqtinchalik
// soketdan yuborilgan taxmin boshqa tashqi portdan chiqadi va
// baribir rad etiladi.
//
// Bitta bosqichda muvaffaqiyat ehtimoli 1-(1-N/65535)^K. N=K=256 da
// bu ~63%.
//
// # Nima ishlaydi va nima yo'q
//
//	symmetric ↔ cone        ishlaydi: cone tomon taxmin qiladi,
//	                        symmetric tomon sepadi
//	symmetric ↔ symmetric   ISHLAMAYDI: taxmin qiluvchining o'z
//	                        tashqi porti ham har oqimda o'zgaradi,
//	                        ya'ni peerning yozuvi uni baribir rad
//	                        etadi. Bunda relay yagona yo'l.
//
// # Nima uchun soketlar kerak
//
// NAT yozuvi ICHKI (manzil, port) juftligiga bog'langan. Bitta
// soketdan yuborilgan hamma paket bitta tashqi portni ulashadi,
// ya'ni sepish uchun haqiqiy soketlar ochish shart.
//
// G'olib soket peer bilan aloqani davom ettiradi: yo'l aynan o'sha
// NAT yozuvi orqali ochilgan va boshqa soketdan yuborilgan paket
// boshqa tashqi portdan chiqib, peerning NAT'ida rad etiladi.
package punch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/freco-dev/cc01/daemon/conn"
)

const (
	// DefaultSockets — sepish uchun ochiladigan soketlar soni.
	DefaultSockets = 256

	// DefaultGuesses — peer IP'sida sinaladigan portlar soni.
	//
	// Sepishdan ko'p: ehtimol N*K ko'paytmasiga bog'liq, lekin
	// narxi bir xil emas. Har bir sepish AYRIM SOKET talab qiladi
	// (fayl deskriptori va goroutine), taxmin esa bitta soketdan
	// yuborilgan yana bitta paket. Shuning uchun taxminlarni
	// ko'paytirish arzonroq.
	//
	// N=256, K=512 da bitta bosqichning ehtimoli
	// 1-exp(-256*512/64511) ≈ 87%.
	DefaultGuesses = 512

	// minEphemeralPort — taxminlar shu oraliqdan tanlanadi.
	//
	// Linux NAT tashqi portni odatda ephemeral oralig'idan beradi.
	// Butun 1..65535 oralig'ini sinash taxminlarni behuda sarflaydi.
	minEphemeralPort = 1024
	maxEphemeralPort = 65535

	// sendSpacing — paketlar orasidagi tanaffus.
	//
	// Bir zumda yuzlab UDP paket yuborish port skanerlashdan
	// farqlanmaydi va yo'ldagi qurilmalar uni to'sishi mumkin.
	// Tanaffus bosqichni bir necha yuz millisekundga cho'zadi —
	// bu relay allaqachon ishlab turgani uchun muammo emas.
	sendSpacing = 300 * time.Microsecond
)

// ErrNoHole — bosqich natija bermadi.
var ErrNoHole = errors.New("punch: teshik ochilmadi")

// Config — bitta bosqichning sozlamalari.
type Config struct {
	// Endpoint — peerning ma'lum (STUN yoki CP bergan) manzili.
	// Sepish AYNAN shu manzilga yuboriladi.
	Endpoint netip.AddrPort

	// Main — datapath soketi. Taxminlar AYNAN shundan yuboriladi:
	// peer bizni shu manzilda kutadi.
	//
	// Javob ham shu soketga qaytadi va odatdagi datapath yo'li
	// bilan qayta ishlanadi — bu tomonda ajratilgan soket kerak
	// emas.
	Main *conn.Bind

	// Sockets, Guesses — 0 bo'lsa standart qiymatlar.
	Sockets int
	Guesses int

	// Payload har chaqiruvda YANGI probe qaytaradi.
	//
	// Funksiya sifatida berilgan, chunki har bir probe o'z nonce'iga
	// ega bo'lishi va sessiya hisoblagichi to'g'ri o'sishi kerak.
	Payload func() ([]byte, error)

	// Accept kelgan paketni tekshiradi. true qaytarsa bosqich
	// muvaffaqiyatli tugaydi.
	//
	// Tekshiruv chaqiruvchida: faqat u sessiya kalitiga ega va
	// paket haqiqatan peerdan kelganini ayta oladi. Busiz har
	// qanday tasodifiy UDP paket "teshik ochildi" deb hisoblanardi.
	Accept func(packet []byte, from netip.AddrPort) bool

	Logger *slog.Logger
}

// Result — muvaffaqiyatli bosqich natijasi.
type Result struct {
	// Bind — g'olib soket. Chaqiruvchi uni O'ZIGA OLADI va yopish
	// mas'uliyati ham unga o'tadi.
	Bind *conn.Bind

	// From — peer qaysi manzildan javob berdi. Bu uning NAT'idagi
	// haqiqiy tashqi manzili va u CP bergan manzildan farq qiladi.
	From netip.AddrPort

	// Attempts — jami yuborilgan probe soni (diagnostika uchun).
	Attempts int
}

func (c Config) withDefaults() Config {
	if c.Sockets <= 0 {
		c.Sockets = DefaultSockets
	}
	if c.Guesses <= 0 {
		c.Guesses = DefaultGuesses
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// Round bitta teshik ochish bosqichini bajaradi.
//
// Muvaffaqiyatsizlikda ErrNoHole qaytadi — bu kutilgan natija, xato
// emas: bir bosqichning ehtimoli ~63%, chaqiruvchi qayta urinadi.
func Round(ctx context.Context, cfg Config) (*Result, error) {
	cfg = cfg.withDefaults()

	if !cfg.Endpoint.IsValid() {
		return nil, errors.New("punch: peer manzili yaroqsiz")
	}
	if cfg.Payload == nil || cfg.Accept == nil {
		return nil, errors.New("punch: Payload va Accept berilishi shart")
	}
	if cfg.Main == nil {
		return nil, errors.New("punch: asosiy soket berilishi shart")
	}

	sockets, err := openSockets(cfg.Sockets)
	if err != nil {
		return nil, err
	}

	// G'olibdan boshqa hamma soket yopiladi. G'olib chaqiruvchiga
	// o'tadi — uning NAT yozuvi yo'lning o'zi.
	var winner *conn.Bind
	defer func() {
		for _, socket := range sockets {
			if socket != winner {
				_ = socket.Close()
			}
		}
	}()

	found := make(chan *Result, 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var readers sync.WaitGroup
	for _, socket := range sockets {
		readers.Add(1)
		go func(socket *conn.Bind) {
			defer readers.Done()
			listen(ctx, socket, cfg, found)
		}(socket)
	}

	attempts := spray(ctx, sockets, cfg)

	// Sepish tugadi — javob yo'lda bo'lishi mumkin, biroz kutamiz.
	select {
	case result := <-found:
		result.Attempts = attempts
		winner = result.Bind
		cancel()
		readers.Wait()
		return result, nil

	case <-time.After(replyWindow):
	case <-ctx.Done():
	}

	cancel()
	readers.Wait()

	// Kutish oynasi tugagunicha kelgan natija bo'lishi mumkin.
	select {
	case result := <-found:
		result.Attempts = attempts
		winner = result.Bind
		return result, nil
	default:
	}

	return nil, fmt.Errorf("%w: %d ta urinish", ErrNoHole, attempts)
}

// replyWindow — sepish tugagandan keyin javobni kutish muddati.
const replyWindow = 2 * time.Second

// openSockets n ta vaqtinchalik soket ochadi.
//
// Qisman muvaffaqiyat qabul qilinadi: tizimda fayl deskriptorlari
// chegarasi bo'lishi mumkin va 256 o'rniga 60 ta soket ochilsa ham
// bosqich ishlaydi, faqat ehtimoli pasayadi. Bittasi ham ochilmasa —
// xato.
func openSockets(n int) ([]*conn.Bind, error) {
	sockets := make([]*conn.Bind, 0, n)

	for range n {
		socket, err := conn.Open(0)
		if err != nil {
			break
		}
		sockets = append(sockets, socket)
	}

	if len(sockets) == 0 {
		return nil, errors.New("punch: birorta ham soket ochilmadi")
	}
	return sockets, nil
}

// spray ikkala yarimni ham bajaradi: har bir soketdan peerning ma'lum
// manziliga, va peer IP'sidagi tasodifiy portlarga.
func spray(ctx context.Context, sockets []*conn.Bind, cfg Config) int {
	var sent int

	// 1-yarim: har bir soketdan MA'LUM manzilga. Bu bizning
	// NAT'imizda len(sockets) ta yozuv ochadi.
	for _, socket := range sockets {
		if ctx.Err() != nil {
			return sent
		}
		if sendProbe(socket, cfg.Endpoint, cfg) {
			sent++
		}
		time.Sleep(sendSpacing)
	}

	// 2-yarim: taxminlar — ASOSIY soketdan.
	//
	// Peerning NAT yozuvi u bizga qaysi manzilga yozgan bo'lsa,
	// faqat o'shandan paket qabul qiladi. Bu bizning STUN e'lon
	// qilgan manzilimiz, ya'ni asosiy soket. Vaqtinchalik soketdan
	// yuborilgan taxmin boshqa tashqi portdan chiqadi va rad
	// etiladi — ya'ni bu tanlov ixtiyoriy emas.
	peerIP := cfg.Endpoint.Addr()
	for range cfg.Guesses {
		if ctx.Err() != nil {
			return sent
		}

		port := uint16(rand.IntN(maxEphemeralPort-minEphemeralPort) + minEphemeralPort)
		if sendProbe(cfg.Main, netip.AddrPortFrom(peerIP, port), cfg) {
			sent++
		}
		time.Sleep(sendSpacing)
	}

	return sent
}

func sendProbe(socket *conn.Bind, target netip.AddrPort, cfg Config) bool {
	payload, err := cfg.Payload()
	if err != nil {
		return false
	}
	return socket.Send(payload, target) == nil
}

// listen bitta soketni kuzatadi.
func listen(ctx context.Context, socket *conn.Bind, cfg Config, found chan<- *Result) {
	buf := make([]byte, 2048)

	for ctx.Err() == nil {
		n, from, err := socket.ReceiveOne(buf, time.Now().Add(200*time.Millisecond))
		if err != nil {
			continue
		}
		if n == 0 || !cfg.Accept(buf[:n], from) {
			continue
		}

		select {
		case found <- &Result{Bind: socket, From: from}:
		default:
			// Boshqa soket avvalroq topdi.
		}
		return
	}
}
