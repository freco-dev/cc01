package inspect

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"time"
)

// Tap — bitta ulanish uchun kuzatuv nuqtasi.
//
// Ikki yo'nalish alohida: so'rovlar ommaviy klientdan lokal
// xizmatga, javoblar teskari yo'nalishda.
type Tap struct {
	recorder *Recorder

	// requests — parse qilingan so'rovlar javob parseriga
	// uzatiladi. HTTP/1.1 da javoblar so'rovlar TARTIBIDA
	// keladi, shuning uchun oddiy navbat yetarli.
	requests chan *pending

	requestWriter  *io.PipeWriter
	responseWriter *io.PipeWriter
}

// pending — javobi hali kelmagan so'rov.
type pending struct {
	request  *http.Request
	exchange Exchange
}

// Tap yangi kuzatuv nuqtasini ochadi.
//
// Qaytgan yozuvchilarga baytlarni AYNAN o'sha ko'rinishda yozish
// kerak; ular oqimga ta'sir qilmaydi. `Close` ni chaqirish shart,
// aks holda parser gorutinalari qolib ketardi.
func (r *Recorder) Tap() *Tap {
	requestReader, requestWriter := io.Pipe()
	responseReader, responseWriter := io.Pipe()

	tap := &Tap{
		recorder:       r,
		requests:       make(chan *pending, 32),
		requestWriter:  requestWriter,
		responseWriter: responseWriter,
	}

	go tap.readRequests(requestReader)
	go tap.readResponses(responseReader)

	return tap
}

// RequestWriter — ommaviy klientdan kelgan baytlar.
func (t *Tap) RequestWriter() io.Writer { return &safeWriter{w: t.requestWriter} }

// ResponseWriter — lokal xizmatdan kelgan baytlar.
func (t *Tap) ResponseWriter() io.Writer { return &safeWriter{w: t.responseWriter} }

// safeWriter kuzatuv xatolarini tunneldan ajratadi.
//
// ⚠️ Busiz jiddiy xato bo'lardi: parser to'xtaganda (masalan
// oqim HTTP emas) quvur yopiladi, keyingi har bir yozuv xato
// qaytaradi, `io.TeeReader` esa uni O'QISH xatosi deb yuqoriga
// uzatadi — va tunnel uzilardi. Inspector qulaylik vositasi,
// uning yiqilishi trafikni to'xtatmasligi kerak.
type safeWriter struct {
	w      io.Writer
	broken bool
}

func (s *safeWriter) Write(p []byte) (int, error) {
	if s.broken {
		return len(p), nil
	}
	if _, err := s.w.Write(p); err != nil {
		s.broken = true
	}
	// Baytlar QABUL QILINDI deb aytamiz: chaqiruvchi uchun
	// kuzatuv shaffof bo'lishi kerak.
	return len(p), nil
}

// Close kuzatuvni yakunlaydi.
func (t *Tap) Close() {
	_ = t.requestWriter.Close()
	_ = t.responseWriter.Close()
}

func (t *Tap) readRequests(reader *io.PipeReader) {
	defer reader.Close()
	defer close(t.requests)

	buffered := bufio.NewReader(reader)

	for {
		request, err := http.ReadRequest(buffered)
		if err != nil {
			// Oqim tugadi yoki HTTP emas — kuzatuvni to'xtatamiz.
			// Tunnel bunga bog'liq emas.
			return
		}

		body, truncated := readBody(request.Body, t.recorder.bodyLimit)
		_ = request.Body.Close()

		exchange := Exchange{
			Started:          time.Now(),
			Method:           request.Method,
			URL:              request.URL.RequestURI(),
			Host:             request.Host,
			Proto:            request.Proto,
			RequestHeaders:   request.Header.Clone(),
			RequestBody:      string(body),
			RequestTruncated: truncated,
		}

		select {
		case t.requests <- &pending{request: request, exchange: exchange}:
		default:
			// Navbat to'lgan — javob parseri ortda qolgan.
			// So'rovni javobsiz yozib qo'yamiz, aks holda u
			// butunlay yo'qolardi.
			exchange.Error = "javob kutilmadi (navbat to'lgan)"
			t.recorder.record(exchange)
		}
	}
}

func (t *Tap) readResponses(reader *io.PipeReader) {
	defer reader.Close()

	buffered := bufio.NewReader(reader)

	for item := range t.requests {
		// So'rov BERILADI: usiz HEAD va 204 javoblarida tananing
		// bor-yo'qligini aniqlab bo'lmaydi va parser oqimni
		// noto'g'ri o'qirdi.
		response, err := http.ReadResponse(buffered, item.request)
		if err != nil {
			item.exchange.Error = describeError(err)
			t.recorder.record(item.exchange)

			// Oqim buzilgan — qolgan so'rovlarni ham javobsiz
			// yozib chiqamiz.
			t.drain(err)
			return
		}

		body, truncated := readBody(response.Body, t.recorder.bodyLimit)

		// ⚠️ Close SHART: u tananing qoldig'ini iste'mol qiladi va
		// keyingi javob to'g'ri joydan o'qiladi. Usiz keep-alive
		// ulanishida ikkinchi javob tananing o'rtasidan boshlab
		// parse qilinardi.
		_ = response.Body.Close()

		item.exchange.Status = response.StatusCode
		item.exchange.ResponseHeaders = response.Header.Clone()
		item.exchange.ResponseBody = string(body)
		item.exchange.ResponseTruncated = truncated
		item.exchange.DurationMS = time.Since(item.exchange.Started).Milliseconds()

		t.recorder.record(item.exchange)
	}
}

// drain qolgan so'rovlarni javobsiz yozib chiqadi.
func (t *Tap) drain(cause error) {
	for item := range t.requests {
		item.exchange.Error = describeError(cause)
		t.recorder.record(item.exchange)
	}
}

func describeError(err error) string {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "ulanish javobsiz uzildi"
	}
	return err.Error()
}

// readBody tanani chegara bilan o'qiydi.
//
// Chegaradan keyingi baytlar ham o'qib tashlanadi — lekin OQIMNI
// SINXRON USHLAB TURISH UCHUN EMAS: buni chaqiruvchidagi
// `Body.Close()` bajaradi (u qoldiqni o'zi iste'mol qiladi).
// Bu yerdagi nusxalash faqat "qirqilgan" bayrog'ini aniqlaydi,
// ya'ni foydalanuvchi ko'rgan tana to'liq emasligini biladi.
func readBody(body io.ReadCloser, limit int) ([]byte, bool) {
	if body == nil {
		return nil, false
	}

	kept, err := io.ReadAll(io.LimitReader(body, int64(limit)))
	if err != nil {
		return kept, false
	}

	// Qolganini tashlab yuboramiz.
	extra, _ := io.Copy(io.Discard, body)

	return kept, extra > 0
}
