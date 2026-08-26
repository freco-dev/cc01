//go:build linux

package tcpolicy

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// attachIngress dasturni interfeysning ingress yo'liga biriktiradi.
//
// Ikki yo'l bor va ular yadro versiyasiga bog'liq:
//
//	TCX      6.6+ — BPF link, avtomatik ajratiladi va boshqa
//	         dasturlar bilan tartiblanadi
//	clsact   eskiroq — qdisc yaratib, unga filtr osiladi
//
// TCX afzal: link yopilganda dastur o'zi ajraladi, ya'ni demon
// halokatli tugasa ham filtr ortda qolmaydi. clsact'da esa qdisc
// va filtr qo'lda tozalanishi kerak.
func attachTC(program *ebpf.Program, index int, direction tcDirection) (func() error, error) {
	attachment, err := link.AttachTCX(link.TCXOptions{
		Program:   program,
		Attach:    direction.tcx,
		Interface: index,
	})
	if err == nil {
		return attachment.Close, nil
	}
	tcxErr := err

	detach, err := attachClsact(program, index, direction)
	if err == nil {
		return detach, nil
	}

	// Ikkala yo'lning ham sababini ko'rsatamiz: faqat oxirgisi
	// operatorni chalg'itardi.
	return nil, fmt.Errorf("tcpolicy: biriktirib bo'lmadi; tcx: %v; clsact: %v",
		tcxErr, err)
}

// tcDirection — kirish yoki chiqish yo'lining biriktirish
// parametrlari.
type tcDirection struct {
	tcx    ebpf.AttachType
	parent uint32
	handle uint16
	name   string
}

var (
	directionIngress = tcDirection{
		tcx:    ebpf.AttachTCXIngress,
		parent: netlink.HANDLE_MIN_INGRESS,
		handle: 1,
		name:   "cc01_tc_ingress",
	}
	directionEgress = tcDirection{
		tcx:    ebpf.AttachTCXEgress,
		parent: netlink.HANDLE_MIN_EGRESS,
		handle: 2,
		name:   "cc01_tc_egress",
	}
)

// attachClsact eski yo'l: clsact qdisc + BPF filtr.
func attachClsact(program *ebpf.Program, index int, direction tcDirection) (func() error, error) {
	link := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Index: index}}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// Qdisc allaqachon bo'lishi mumkin — boshqa vosita qo'ygan
	// bo'lsa uni buzib tashlamaymiz.
	qdiscCreated := false
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if !errors.Is(err, errFileExists) {
			return nil, fmt.Errorf("clsact qdisc: %w", err)
		}
	} else {
		qdiscCreated = true
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: index,
			Parent:    direction.parent,
			Handle:    netlink.MakeHandle(0, direction.handle),
			Protocol:  protocolAll,
			Priority:  1,
		},
		Fd:           program.FD(),
		Name:         direction.name,
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		if qdiscCreated {
			_ = netlink.QdiscDel(qdisc)
		}
		return nil, fmt.Errorf("bpf filtri: %w", err)
	}

	return func() error {
		var errs []error
		errs = append(errs, netlink.FilterDel(filter))

		// Qdisc'ni faqat O'ZIMIZ yaratgan bo'lsak o'chiramiz:
		// boshqa vosita qo'ygan bo'lsa, uni olib tashlash o'sha
		// vositaning filtrlarini ham yo'q qilardi.
		if qdiscCreated {
			errs = append(errs, netlink.QdiscDel(qdisc))
		}

		_ = link
		return errors.Join(errs...)
	}, nil
}
