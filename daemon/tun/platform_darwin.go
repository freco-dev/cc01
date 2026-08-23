//go:build darwin

package tun

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// macOS'da manzil va marshrut sozlash `ifconfig`/`route` orqali bajariladi.
//
// Nega shell: utun interfeysini sozlash uchun BSD'da SIOCAIFADDR_IN6
// ioctl'ini qo'lda yig'ish kerak bo'ladi — bu ancha kod va har bir macOS
// versiyasida sinovdan o'tkazish talab qiladi. Hujjatlar (DEV_SPEC §3.2)
// macOS'ni ikkilamchi platforma deb belgilaydi: to'liq funksiya Linux'da,
// bu yerda esa ishlaydigan fallback yetarli.
func configure(name string, cfg Config) error {
	for _, prefix := range cfg.Addresses {
		// macOS utun nuqta-nuqta interfeys: manzil ikki marta beriladi.
		if err := run("ifconfig", name, "inet6", prefix.Addr().String(),
			prefix.Addr().String(), "prefixlen", "128"); err != nil {
			return fmt.Errorf("tun: manzil qo'shish (%v): %w", prefix, err)
		}
	}

	if err := run("ifconfig", name, "mtu", fmt.Sprint(cfg.MTU)); err != nil {
		return fmt.Errorf("tun: MTU: %w", err)
	}
	if err := run("ifconfig", name, "up"); err != nil {
		return fmt.Errorf("tun: interfeysni ko'tarish: %w", err)
	}

	for _, prefix := range cfg.Routes {
		// macOS'da ajratilgan routing jadvali yo'q, shuning uchun
		// marshrutlar asosiy jadvalga tushadi. Close() ularni aynan
		// shu ro'yxat bo'yicha o'chiradi.
		if err := run("route", "-q", "-n", "add", "-inet6",
			prefix.String(), "-interface", name); err != nil {
			return fmt.Errorf("tun: marshrut qo'shish (%v): %w", prefix, err)
		}
	}

	return nil
}

// cleanup: interfeys yopilganda macOS unga tegishli marshrutlarni o'zi
// olib tashlaydi, shuning uchun bu yerda qo'shimcha ish yo'q.
func cleanup(string) error { return nil }

func run(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err == nil {
		return nil
	}

	message := strings.TrimSpace(string(output))
	if message == "" {
		return err
	}
	return errors.New(message)
}

// macOS'da ajratilgan routing jadvali yo'q — `netstat` chiqishini
// parse qilib "bizniki" marshrutlarni ajratib bo'lmaydi. Shuning uchun
// rekonsiliatsiya o'zi qo'ygan ro'yxatga tayanadi.
func listRoutes(string) ([]netipPrefix, error) {
	return nil, ErrRoutesNotEnumerable
}

func addRouteFor(name string, prefix netipPrefix) error {
	if err := run("route", "-q", "-n", "add", "-inet6",
		prefix.String(), "-interface", name); err != nil {
		return fmt.Errorf("tun: marshrut qo'shish (%v): %w", prefix, err)
	}
	return nil
}

func delRouteFor(name string, prefix netipPrefix) error {
	if err := run("route", "-q", "-n", "delete", "-inet6",
		prefix.String(), "-interface", name); err != nil {
		return fmt.Errorf("tun: marshrut o'chirish (%v): %w", prefix, err)
	}
	return nil
}
