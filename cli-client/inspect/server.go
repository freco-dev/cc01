package inspect

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrNotLoopback — inspector faqat lokal manzilda ochiladi.
var ErrNotLoopback = errors.New("inspect: manzil loopback bo'lishi shart")

// Server — `127.0.0.1:4040` dagi kuzatuv sahifasi.
type Server struct {
	recorder *Recorder
	listener net.Listener
	server   *http.Server
}

// Listen kuzatuv sahifasini ochadi.
//
// ⚠️ Manzil LOOPBACK bo'lishi shart va bu tekshiruvni chetlab
// o'tib bo'lmaydi. Sahifada so'rovlarning to'liq sarlavhalari va
// tanalari ko'rinadi — ular ichida `Authorization`, cookie va
// parollar bo'ladi. Uni tarmoqqa chiqarish tunneldan o'tgan
// hamma sirni ochib qo'yardi.
func Listen(recorder *Recorder, address string) (*Server, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("inspect: manzil host:port bo'lishi kerak: %w", err)
	}
	if err := requireLoopback(host); err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("inspect: tinglash (%s): %w", address, err)
	}

	inspector := &Server{recorder: recorder, listener: listener}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", inspector.handlePage)
	mux.HandleFunc("GET /api/exchanges", inspector.handleList)
	mux.HandleFunc("GET /api/stream", inspector.handleStream)
	mux.HandleFunc("POST /api/clear", inspector.handleClear)

	inspector.server = &http.Server{
		Handler: mux,
		// Stream uzun yashaydi, shuning uchun yozish chegarasi yo'q.
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = inspector.server.Serve(listener) }()

	return inspector, nil
}

// requireLoopback manzil lokal ekanini tekshiradi.
func requireLoopback(host string) error {
	if host == "" || host == "localhost" {
		return nil
	}

	addr, err := netipParse(host)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNotLoopback, host)
	}
	if !addr.IsLoopback() {
		return fmt.Errorf("%w: %s", ErrNotLoopback, host)
	}
	return nil
}

// Addr — sahifaning manzili.
func (s *Server) Addr() string { return s.listener.Addr().String() }

// URL — brauzerda ochish uchun manzil.
func (s *Server) URL() string { return "http://" + s.Addr() }

// Close sahifani yopadi.
func (s *Server) Close() error { return s.server.Close() }

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.recorder.Exchanges())
}

func (s *Server) handleClear(w http.ResponseWriter, _ *http.Request) {
	s.recorder.Clear()
	w.WriteHeader(http.StatusNoContent)
}

// handleStream jonli oqimni Server-Sent Events bilan uzatadi.
//
// SSE tanlandi: WebSocket kabi qo'shimcha kutubxona talab
// qilmaydi va bizga faqat bir tomonlama oqim kerak.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming qo'llab-quvvatlanmaydi", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	updates, cancel := s.recorder.Subscribe()
	defer cancel()

	// Yurak urishi: proksi va brauzer bo'sh ulanishni yopib
	// yubormasligi uchun.
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case exchange, open := <-updates:
			if !open {
				return
			}
			encoded, err := json.Marshal(exchange)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", encoded)
			flusher.Flush()

		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = strings.NewReader(pageHTML).WriteTo(w)
}
