package ipc

import (
	"fmt"
	"os"
	"runtime"

	"github.com/freco-dev/cc01/daemon/route"
	"github.com/freco-dev/cc01/daemon/tun"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// RunChecks muhitni tekshiradi (DEV_SPEC §3.1 dagi PREFLIGHT).
//
// Har bir muvaffaqiyatsiz tekshiruv `remediation` bilan keladi:
// foydalanuvchi "nima qilishim kerak" degan savolga javobni shu
// yerdan olishi kerak, hujjatlarni qidirmasdan.
func RunChecks(routes *route.Status) []*cc01v1.Check {
	checks := []*cc01v1.Check{
		checkPlatform(),
		checkTunDevice(),
		checkPrivileges(),
		checkMTU(),
	}

	// Statik rejimda rekonsilyator yo'q — bo'lmagan narsa haqida
	// "hammasi joyida" deb yozgandan ko'ra, umuman yozmagan yaxshi.
	if routes != nil {
		checks = append(checks, checkRoutes(routes))
	}
	return checks
}

func checkRoutes(routes *route.Status) *cc01v1.Check {
	count := routes.Count

	if !routes.Synced {
		return fail("marshrutlar",
			fmt.Sprintf("oxirgi moslashtirish muvaffaqiyatsiz (%d ta kutilgan)", count),
			"demon loglarini ko'ring: journalctl -u cc01d\n"+
				"yadro jadvalini tekshiring: ip -6 route show table "+
				fmt.Sprint(tun.RouteTable))
	}

	return ok("marshrutlar",
		fmt.Sprintf("%d ta, %d-jadval bilan mos", count, tun.RouteTable))
}

func checkPlatform() *cc01v1.Check {
	switch runtime.GOOS {
	case "linux":
		return ok("platforma", runtime.GOOS+"/"+runtime.GOARCH+" — to'liq qo'llab-quvvatlanadi")

	case "darwin":
		return warn("platforma",
			runtime.GOOS+"/"+runtime.GOARCH+" — ikkilamchi platforma",
			"eBPF va ajratilgan routing jadvali yo'q; to'liq funksiya Linux'da")

	default:
		return fail("platforma",
			runtime.GOOS+" qo'llab-quvvatlanmaydi",
			"Linux (tavsiya) yoki macOS ishlating")
	}
}

func checkTunDevice() *cc01v1.Check {
	if runtime.GOOS != "linux" {
		return ok("tun qurilmasi", "bu platformada alohida qurilma fayli kerak emas")
	}

	const device = "/dev/net/tun"

	info, err := os.Stat(device)
	if os.IsNotExist(err) {
		return fail("tun qurilmasi", device+" mavjud emas",
			"modulni yuklang: sudo modprobe tun\n"+
				"konteynerda: --device /dev/net/tun")
	}
	if err != nil {
		return fail("tun qurilmasi", err.Error(), "qurilma fayliga kirishni tekshiring")
	}

	if info.Mode()&os.ModeCharDevice == 0 {
		return fail("tun qurilmasi", device+" belgili qurilma emas",
			"tun modulini qayta yuklang")
	}

	return ok("tun qurilmasi", device+" mavjud")
}

func checkPrivileges() *cc01v1.Check {
	if os.Geteuid() == 0 {
		return ok("imtiyozlar", "root sifatida ishlayapti")
	}

	// Root bo'lmasdan ham ishlash mumkin, agar CAP_NET_ADMIN berilgan
	// bo'lsa (DEV_SPEC §7.2 S-5: to'liq root shart emas).
	return warn("imtiyozlar",
		fmt.Sprintf("uid=%d, root emas", os.Geteuid()),
		"TUN yaratish uchun CAP_NET_ADMIN kerak:\n"+
			"  sudo setcap cap_net_admin+ep $(which cc01d)\n"+
			"yoki systemd unit'da: AmbientCapabilities=CAP_NET_ADMIN")
}

func checkMTU() *cc01v1.Check {
	return ok("MTU",
		fmt.Sprintf("%d bayt — IPv6 minimumi, fragmentatsiyasiz", tun.DefaultMTU))
}

func ok(name, detail string) *cc01v1.Check {
	return &cc01v1.Check{Name: name, Status: cc01v1.Check_STATUS_OK, Detail: detail}
}

func warn(name, detail, remediation string) *cc01v1.Check {
	return &cc01v1.Check{
		Name: name, Status: cc01v1.Check_STATUS_WARN,
		Detail: detail, Remediation: remediation,
	}
}

func fail(name, detail, remediation string) *cc01v1.Check {
	return &cc01v1.Check{
		Name: name, Status: cc01v1.Check_STATUS_FAIL,
		Detail: detail, Remediation: remediation,
	}
}
