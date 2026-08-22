package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/freco-dev/cc01/daemon/ipc"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DefaultSocketHint — yordamda ko'rsatiladigan standart yo'l.
const DefaultSocketHint = ipc.DefaultSocket

// Chiqish kodlari (DEV_SPEC §5.2).
const (
	exitOK           = 0
	exitBadArgument  = 2
	exitNoDaemon     = 10
	exitNoPermission = 11
)

var (
	// errNoDaemon — demonga ulanib bo'lmadi.
	errNoDaemon = errors.New("demon ishlamayapti")

	// errNoPermission — soketga kirish taqiqlangan.
	errNoPermission = errors.New("soketga kirish taqiqlangan")
)

func exitCodeFor(err error) int {
	switch {
	case errors.Is(err, errNoDaemon):
		return exitNoDaemon
	case errors.Is(err, errNoPermission):
		return exitNoPermission
	case errors.Is(err, flag.ErrHelp):
		return exitBadArgument
	default:
		return 1
	}
}

// connect demonga ulanadi va uning holatini tekshiradi.
//
// gRPC ulanishi dangasa: `NewClient` soket mavjudligini tekshirmaydi.
// Shuning uchun birinchi chaqiruvni shu yerda bajarib, xatoni
// tushunarli shaklga keltiramiz.
func connect(socket string) (cc01v1.DaemonServiceClient, func(), error) {
	conn, err := ipc.Dial(socket)
	if err != nil {
		return nil, nil, err
	}

	client := cc01v1.NewDaemonServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.Status(ctx, &cc01v1.StatusRequest{}); err != nil {
		_ = conn.Close()
		return nil, nil, translate(err, socket)
	}

	return client, func() { _ = conn.Close() }, nil
}

// translate gRPC xatosini foydalanuvchi tushunadigan shaklga keltiradi.
func translate(err error, socket string) error {
	if status.Code(err) != codes.Unavailable {
		return err
	}

	if info, statErr := os.Stat(socket); statErr == nil {
		// Soket bor, lekin ulanib bo'lmadi — ehtimol ruxsat yo'q.
		if info.Mode()&0o060 != 0 && os.Geteuid() != 0 {
			return fmt.Errorf("%w: %s\n  demon guruhiga qo'shiling yoki sudo bilan ishga tushiring",
				errNoPermission, socket)
		}
	}

	return fmt.Errorf("%w: %s\n  ishga tushiring: systemctl start cc01d", errNoDaemon, socket)
}

// socketFlag umumiy `--socket` bayrog'ini qo'shadi.
func socketFlag(set *flag.FlagSet) *string {
	return set.String("socket", ipc.DefaultSocket, "demon soketi")
}
