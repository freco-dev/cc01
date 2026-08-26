package inspect

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func startServer(t *testing.T, recorder *Recorder) *Server {
	t.Helper()

	server, err := Listen(recorder, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	return server
}

// ⚠️ Bu inspector'dagi eng muhim tekshiruv. Sahifada so'rovlarning
// to'liq sarlavhalari va tanalari ko'rinadi — ular ichida
// `Authorization`, cookie va parollar bo'ladi. Uni tarmoqqa
// chiqarish tunneldan o'tgan hamma sirni ochib qo'yardi.
func TestListen_RefusesNonLoopback(t *testing.T) {
	recorder := New(Options{})

	for _, address := range []string{
		"0.0.0.0:0",
		"192.168.1.10:4040",
		"[::]:4040",
		"8.8.8.8:4040",
	} {
		server, err := Listen(recorder, address)
		if err == nil {
			_ = server.Close()
			t.Errorf("%s qabul qilindi", address)
			continue
		}
		if !errors.Is(err, ErrNotLoopback) {
			t.Errorf("%s: xato sababi boshqa: %v", address, err)
		}
	}
}

func TestListen_AcceptsLoopback(t *testing.T) {
	recorder := New(Options{})

	for _, address := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		server, err := Listen(recorder, address)
		if err != nil {
			t.Errorf("%s rad etildi: %v", address, err)
			continue
		}
		_ = server.Close()
	}
}

func TestServer_ListsExchanges(t *testing.T) {
	recorder := New(Options{})
	server := startServer(t, recorder)

	feed(t, recorder,
		"GET /birinchi HTTP/1.1\r\nHost: demo\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

	response, err := http.Get(server.URL() + "/api/exchanges")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer response.Body.Close()

	var exchanges []Exchange
	if err := json.NewDecoder(response.Body).Decode(&exchanges); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if len(exchanges) != 1 {
		t.Fatalf("%d almashuv", len(exchanges))
	}
	if exchanges[0].URL != "/birinchi" {
		t.Errorf("URL %q", exchanges[0].URL)
	}
}

// "Real vaqtda ko'rinadi" — bu mezonning o'zi.
func TestServer_StreamsLive(t *testing.T) {
	recorder := New(Options{})
	server := startServer(t, recorder)

	response, err := http.Get(server.URL() + "/api/stream")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer response.Body.Close()

	if got := response.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type %q", got)
	}

	// Obuna o'rnatilishini kutamiz: aks holda almashuv oqim
	// boshlanishidan oldin yozilib, test tasodifan yiqilardi.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		recorder.mu.RLock()
		count := len(recorder.subscribers)
		recorder.mu.RUnlock()
		if count > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Sinxron: obunachining kanali buferli, ya'ni hodisa biz
	// o'qishni boshlagunimizcha saqlanib turadi. Alohida
	// gorutinada `t.Fatalf` chaqirish esa taqiqlangan.
	feed(t, recorder,
		"GET /jonli HTTP/1.1\r\nHost: demo\r\n\r\n",
		"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")

	reader := bufio.NewReader(response.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("oqim uzildi: %v", err)
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var exchange Exchange
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &exchange); err != nil {
			t.Fatalf("JSON: %v", err)
		}
		if exchange.URL != "/jonli" {
			t.Errorf("URL %q", exchange.URL)
		}
		if exchange.Status != 201 {
			t.Errorf("status %d", exchange.Status)
		}
		return
	}
}

func TestServer_Clear(t *testing.T) {
	recorder := New(Options{})
	server := startServer(t, recorder)

	feed(t, recorder,
		"GET /x HTTP/1.1\r\nHost: demo\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	if len(recorder.Exchanges()) == 0 {
		t.Fatal("almashuv yozilmadi")
	}

	response, err := http.Post(server.URL()+"/api/clear", "", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = response.Body.Close()

	if got := recorder.Exchanges(); len(got) != 0 {
		t.Errorf("%d almashuv qoldi", len(got))
	}
}

func TestServer_ServesPage(t *testing.T) {
	server := startServer(t, New(Options{}))

	response, err := http.Get(server.URL() + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("o'qish: %v", err)
	}

	// Sahifa TASHQI bog'liqliksiz bo'lishi kerak: inspector lokal
	// vosita va CDN ga chiqishi kerak emas.
	for _, forbidden := range []string{"https://", "http://cdn", "//unpkg", "//cdnjs"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("sahifada tashqi manba: %s", forbidden)
		}
	}
	if !strings.Contains(string(body), "EventSource") {
		t.Error("jonli oqim ulanmagan")
	}
}

// Eng eski yozuvlar tashlanishi kerak — inspector xotirada ishlaydi.
func TestRecorder_RingBuffer(t *testing.T) {
	recorder := New(Options{Capacity: 3})

	for i := range 10 {
		recorder.record(Exchange{URL: string(rune('a' + i))})
	}

	got := recorder.Exchanges()
	if len(got) != 3 {
		t.Fatalf("%d yozuv, 3 kutilgan edi", len(got))
	}
	if got[0].URL != "h" || got[2].URL != "j" {
		t.Errorf("eng yangi uchtasi qolmadi: %s %s %s",
			got[0].URL, got[1].URL, got[2].URL)
	}
}

// Sekin obunachi tunnelni sekinlashtirmasligi kerak.
func TestRecorder_SlowSubscriberDoesNotBlock(t *testing.T) {
	recorder := New(Options{})

	_, cancel := recorder.Subscribe()
	defer cancel()

	done := make(chan struct{})
	go func() {
		// Obunachi hech nima o'qimaydi; kanal to'ladi.
		for i := range 1000 {
			recorder.record(Exchange{URL: string(rune(i))})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("sekin obunachi yozuvni bloklab qo'ydi")
	}
}
