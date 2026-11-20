package access

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/freco-dev/cc01/core-server/config"
	"google.golang.org/grpc"
)

// AP qayta tiklanganda edge→AP kanali uzoq kutib qolmasligi kerak:
// gRPC'ning standart backoff'i (MaxDelay 120 s) bilan AP bir necha daqiqa
// yo'q bo'lsa, u qaytgach ham kanal ~2 daqiqagacha TRANSIENT_FAILURE'da
// qolardi va har Renew/Authorize darhol Unavailable olardi — 60 s
// kafolati buzilardi (DEV_SPEC §8).
//
// Test ulanish urinishlari orasidagi pauzalarni o'lchaydi: standart
// backoff'da 4-pauza ≈4.1 s (1, 1.6, 2.56, 4.1, …), bizda esa hech qachon
// MaxDelay·(1+jitter) dan oshmaydi.
func TestDial_ReconnectBackoffIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: ~8 s davom etadi")
	}
	t.Parallel()

	var (
		mu       sync.Mutex
		attempts []time.Time
	)
	refuse := grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		mu.Lock()
		attempts = append(attempts, time.Now())
		mu.Unlock()
		return nil, errors.New("connection refused (sinov)")
	})

	client, err := Dial(Options{
		Address:     "passthrough:///127.0.0.1:0", // dialer rad etadi; loopback — shifrsiz
		Timeout:     100 * time.Millisecond,
		DialOptions: []grpc.DialOption{refuse},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Eng katta ruxsat etilgan pauza: rad etilgan ulanishda urinishlar
	// orasida faqat backoff (MaxDelay·(1+jitter)) bor, ustiga sekin CI
	// uchun zaxira. Standart backoff'ning 4-pauzasi (≥3.3 s) undan katta.
	b := reconnectParams.Backoff
	limit := time.Duration(float64(b.MaxDelay)*(1+b.Jitter)) + 500*time.Millisecond
	if limit >= 3300*time.Millisecond {
		t.Fatalf("test chegarasi %s standart backoff'ni ajrata olmaydi", limit)
	}

	// Kanal bo'sh turib qolmasligi uchun RPC'lar yuborib turiladi (Renew
	// tsikli kabi).
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = client.Renew(context.Background(), Request{Token: "tok", Subdomain: "myapp"})

		mu.Lock()
		last := time.Time{}
		if n := len(attempts); n > 0 {
			last = attempts[n-1]
		}
		mu.Unlock()
		if !last.IsZero() && time.Since(last) > limit {
			t.Fatalf("ulanish urinishlari orasidagi pauza %s dan oshdi — backoff cheklanmagan",
				limit)
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(attempts) < 4 {
		t.Fatalf("kamida 4 ta ulanish urinishi kutilgan, %d bo'ldi", len(attempts))
	}
	for i := 1; i < len(attempts); i++ {
		if gap := attempts[i].Sub(attempts[i-1]); gap > limit {
			t.Errorf("%d-pauza %s > %s", i, gap, limit)
		}
	}
}

// Qayta ulanish chegarasi konfiguratsiyadagi byudjetga sig'adi:
// config.AccessReconnectMax 60 s kafolati hisobida ishlatiladi.
func TestReconnectDelayMaxFitsConfigBudget(t *testing.T) {
	if reconnectDelayMax > config.AccessReconnectMax {
		t.Errorf("reconnectDelayMax %s > config.AccessReconnectMax %s",
			reconnectDelayMax, config.AccessReconnectMax)
	}
	want := reconnectParams.MinConnectTimeout +
		time.Duration(float64(reconnectParams.Backoff.MaxDelay)*(1+reconnectParams.Backoff.Jitter))
	if reconnectDelayMax < want {
		t.Errorf("reconnectDelayMax %s < MinConnectTimeout + MaxDelay·(1+jitter) = %s",
			reconnectDelayMax, want)
	}
}
