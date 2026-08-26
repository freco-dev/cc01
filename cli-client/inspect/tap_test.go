package inspect

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// feed tap'ga so'rov va javob baytlarini beradi va yozilgan
// almashuvlarni qaytaradi.
func feed(t *testing.T, recorder *Recorder, requests, responses string) []Exchange {
	t.Helper()

	tap := recorder.Tap()

	if _, err := io.Copy(tap.RequestWriter(), strings.NewReader(requests)); err != nil {
		t.Fatalf("so'rovlar: %v", err)
	}
	if _, err := io.Copy(tap.ResponseWriter(), strings.NewReader(responses)); err != nil {
		t.Fatalf("javoblar: %v", err)
	}
	tap.Close()

	return waitFor(t, recorder, strings.Count(requests, "HTTP/1.1\r\n"))
}

// waitFor kutilgan sondagi almashuv yozilishini kutadi.
func waitFor(t *testing.T, recorder *Recorder, want int) []Exchange {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := recorder.Exchanges(); len(got) >= want {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return recorder.Exchanges()
}

func TestTap_RecordsRequestAndResponse(t *testing.T) {
	recorder := New(Options{})

	exchanges := feed(t, recorder,
		"GET /salom?a=1 HTTP/1.1\r\nHost: demo.cc01.uz\r\nX-Test: bor\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nsalom")

	if len(exchanges) != 1 {
		t.Fatalf("%d almashuv yozildi, 1 kutilgan edi", len(exchanges))
	}

	got := exchanges[0]
	if got.Method != "GET" {
		t.Errorf("metod %q", got.Method)
	}
	if got.URL != "/salom?a=1" {
		t.Errorf("URL %q", got.URL)
	}
	if got.Host != "demo.cc01.uz" {
		t.Errorf("host %q", got.Host)
	}
	if got.RequestHeaders.Get("X-Test") != "bor" {
		t.Errorf("sarlavha yo'qoldi: %v", got.RequestHeaders)
	}
	if got.Status != 200 {
		t.Errorf("status %d", got.Status)
	}
	if got.ResponseBody != "salom" {
		t.Errorf("javob tanasi %q", got.ResponseBody)
	}
	if got.Error != "" {
		t.Errorf("xato: %s", got.Error)
	}
}

// Keep-alive: bitta ulanishda bir nechta so'rov ketma-ket keladi
// va ular TARTIB bilan javoblarga mos kelishi kerak.
func TestTap_HandlesKeepAlive(t *testing.T) {
	recorder := New(Options{})

	var requests, responses strings.Builder
	for i := range 3 {
		fmt.Fprintf(&requests, "GET /%d HTTP/1.1\r\nHost: demo\r\n\r\n", i)
		fmt.Fprintf(&responses,
			"HTTP/1.1 %d OK\r\nContent-Length: 1\r\n\r\n%d", 200+i, i)
	}

	exchanges := feed(t, recorder, requests.String(), responses.String())

	if len(exchanges) != 3 {
		t.Fatalf("%d almashuv, 3 kutilgan edi", len(exchanges))
	}
	for i, got := range exchanges {
		if want := fmt.Sprintf("/%d", i); got.URL != want {
			t.Errorf("%d: URL %q, %q kutilgan edi", i, got.URL, want)
		}
		if want := 200 + i; got.Status != want {
			t.Errorf("%d: status %d, %d kutilgan edi", i, got.Status, want)
		}
	}
}

// So'rov tanasi ham yozilishi kerak.
func TestTap_RecordsRequestBody(t *testing.T) {
	recorder := New(Options{})

	exchanges := feed(t, recorder,
		"POST /yuborish HTTP/1.1\r\nHost: demo\r\nContent-Length: 9\r\n\r\nsalom cc0",
		"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")

	if len(exchanges) != 1 {
		t.Fatalf("%d almashuv", len(exchanges))
	}
	if exchanges[0].RequestBody != "salom cc0" {
		t.Errorf("so'rov tanasi %q", exchanges[0].RequestBody)
	}
}

// Katta tana chegaralanishi kerak — inspector xotirada ishlaydi.
func TestTap_TruncatesLargeBody(t *testing.T) {
	recorder := New(Options{BodyLimit: 16})

	big := strings.Repeat("x", 1000)
	exchanges := feed(t, recorder,
		"GET / HTTP/1.1\r\nHost: demo\r\n\r\n",
		fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(big), big))

	if len(exchanges) != 1 {
		t.Fatalf("%d almashuv", len(exchanges))
	}
	got := exchanges[0]
	if len(got.ResponseBody) != 16 {
		t.Errorf("tana %d bayt saqlandi, 16 kutilgan edi", len(got.ResponseBody))
	}
	if !got.ResponseTruncated {
		t.Error("qirqilgani belgilanmadi")
	}
}

// Chegaradan oshgan tanadan keyin oqim sinxron qolishi kerak:
// aks holda parser keyingi javobni tananing o'rtasidan boshlab
// o'qib, butun kuzatuvni buzardi.
//
// (Amalda buni `Body.Close()` ta'minlaydi — test aynan shu
// bog'liqlikni qo'riqlaydi.)
func TestTap_ContinuesAfterTruncatedBody(t *testing.T) {
	recorder := New(Options{BodyLimit: 4})

	big := strings.Repeat("y", 100)
	requests := "GET /birinchi HTTP/1.1\r\nHost: demo\r\n\r\n" +
		"GET /ikkinchi HTTP/1.1\r\nHost: demo\r\n\r\n"
	responses := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s"+
			"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", len(big), big)

	exchanges := feed(t, recorder, requests, responses)

	if len(exchanges) != 2 {
		t.Fatalf("%d almashuv, 2 kutilgan edi — qirqilgan tanadan keyin "+
			"oqim buzilgan", len(exchanges))
	}
	if exchanges[1].URL != "/ikkinchi" || exchanges[1].Status != 204 {
		t.Errorf("ikkinchi almashuv: %s → %d", exchanges[1].URL, exchanges[1].Status)
	}
}

// Javob kelmasa ham so'rov yozilishi kerak: aks holda uzilgan
// so'rovlar butunlay ko'rinmasdi va aynan ular qiziq.
func TestTap_RecordsRequestWithoutResponse(t *testing.T) {
	recorder := New(Options{})

	exchanges := feed(t, recorder,
		"GET /uzilgan HTTP/1.1\r\nHost: demo\r\n\r\n", "")

	if len(exchanges) != 1 {
		t.Fatalf("%d almashuv, 1 kutilgan edi", len(exchanges))
	}
	if exchanges[0].Error == "" {
		t.Error("xato belgilanmadi")
	}
	if exchanges[0].Status != 0 {
		t.Errorf("status %d, 0 kutilgan edi", exchanges[0].Status)
	}
}

// HTTP bo'lmagan oqim kuzatuvni to'xtatadi, lekin yiqitmaydi.
func TestTap_SurvivesNonHTTP(t *testing.T) {
	recorder := New(Options{})

	tap := recorder.Tap()
	if _, err := tap.RequestWriter().Write(bytes.Repeat([]byte{0xff}, 512)); err != nil {
		t.Fatalf("yozish: %v", err)
	}
	tap.Close()

	// Panika bo'lmasligi va almashuv yozilmasligi kerak.
	time.Sleep(50 * time.Millisecond)
	if got := recorder.Exchanges(); len(got) != 0 {
		t.Errorf("%d almashuv yozildi", len(got))
	}
}

// HEAD javobida tana yo'q — so'rov berilmasa parser buni bilmaydi
// va keyingi javobni tana deb o'qib, oqimni buzardi.
func TestTap_HandlesHEAD(t *testing.T) {
	recorder := New(Options{})

	requests := "HEAD /bosh HTTP/1.1\r\nHost: demo\r\n\r\n" +
		"GET /keyin HTTP/1.1\r\nHost: demo\r\n\r\n"
	responses := "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

	exchanges := feed(t, recorder, requests, responses)

	if len(exchanges) != 2 {
		t.Fatalf("%d almashuv, 2 kutilgan edi — HEAD dan keyin oqim buzilgan",
			len(exchanges))
	}
	if exchanges[1].URL != "/keyin" || exchanges[1].ResponseBody != "ok" {
		t.Errorf("ikkinchi almashuv: %s → %q",
			exchanges[1].URL, exchanges[1].ResponseBody)
	}
}

// ⚠️ Faza 3 dagi eng xavfli nuqta: kuzatuv yiqilsa TUNNEL ham
// uzilib qolishi mumkin edi.
//
// Parser to'xtaganda (oqim HTTP emas) quvur yopiladi va keyingi
// har bir yozuv xato qaytaradi. `io.TeeReader` uni O'QISH xatosi
// deb yuqoriga uzatadi — ya'ni `io.Copy` to'xtab, ulanish
// yopilardi. Inspector qulaylik vositasi va uning yiqilishi
// trafikni to'xtatmasligi kerak.
func TestTap_WriterStaysUsableAfterParserStops(t *testing.T) {
	recorder := New(Options{})
	tap := recorder.Tap()

	writer := tap.RequestWriter()

	// Parser to'xtashi uchun unga TUGALLANGAN, lekin yaroqsiz
	// so'rov qatori kerak. Shunchaki tasodifiy baytlar yetmaydi:
	// `ReadRequest` yangi qatorni kutib bloklanib turadi va
	// parser umuman to'xtamaydi.
	if _, err := writer.Write([]byte("BU HTTP EMAS\r\n\r\n")); err != nil {
		t.Fatalf("birinchi yozuv: %v", err)
	}

	// Parser haqiqatan to'xtaganini kutamiz: quvur yopilgach
	// yozuvlar xato qaytara boshlaydi.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := tap.requestWriter.Write([]byte("x")); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := tap.requestWriter.Write([]byte("x")); err == nil {
		t.Fatal("parser to'xtamadi — test hech nimani tekshirmaydi")
	}

	// Tunnel baytlarni yuborishda davom etadi.
	for i := range 100 {
		n, err := writer.Write([]byte("keyingi baytlar"))
		if err != nil {
			t.Fatalf("yozuv %d xato qaytardi: %v — tunnel uzilardi", i, err)
		}
		if n != len("keyingi baytlar") {
			t.Fatalf("yozuv %d: %d bayt qabul qilindi, %d kutilgan edi",
				i, n, len("keyingi baytlar"))
		}
	}

	tap.Close()
}

// Kuzatuv yopilgandan keyin ham yozuv xavfsiz bo'lishi kerak.
func TestTap_WriteAfterCloseIsSafe(t *testing.T) {
	recorder := New(Options{})
	tap := recorder.Tap()

	writer := tap.ResponseWriter()
	tap.Close()

	if _, err := writer.Write([]byte("kech qolgan baytlar")); err != nil {
		t.Errorf("yopilgandan keyingi yozuv xato qaytardi: %v", err)
	}
}
