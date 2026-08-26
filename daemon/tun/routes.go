package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// ErrRoutesNotEnumerable — platforma yadrodagi marshrutlarni o'qib bera
// olmaydi. Bunda rekonsiliatsiya o'zi qo'ygan marshrutlar ro'yxatiga
// tayanadi: bu tashqaridan qilingan o'zgarishni ko'rmaydi, lekin
// qo'llanilgan holatni to'g'ri kuzatadi.
var ErrRoutesNotEnumerable = errors.New("tun: marshrutlarni sanab bo'lmaydi")

// RouteDiff — bitta rekonsiliatsiya bosqichida haqiqatda nima
// o'zgargani. Bo'sh diff — holat allaqachon to'g'ri degani.
type RouteDiff struct {
	Added   []netip.Prefix
	Removed []netip.Prefix
}

// Empty — hech narsa o'zgarmadimi.
func (d RouteDiff) Empty() bool { return len(d.Added) == 0 && len(d.Removed) == 0 }

func (d RouteDiff) String() string {
	if d.Empty() {
		return "o'zgarishsiz"
	}

	var parts []string
	if len(d.Added) > 0 {
		parts = append(parts, "+"+joinPrefixes(d.Added))
	}
	if len(d.Removed) > 0 {
		parts = append(parts, "-"+joinPrefixes(d.Removed))
	}
	return strings.Join(parts, " ")
}

// SetRoutes yadrodagi marshrut to'plamini `desired` ga keltiradi:
// yetishmagani qo'shiladi, ortiqchasi olib tashlanadi.
//
// Nega har safar to'liq solishtirish, o'zgarishlarni kuzatib borish
// emas: yadro holati biz bilmagan sabablarga ko'ra o'zgarishi mumkin —
// interfeys tushib qolgan, boshqa jarayon aralashgan, oldingi cc01d
// SIGKILL bilan o'lgan. Har safar haqiqiy holatdan boshlash bu
// hollarning hammasini bir xil hal qiladi.
//
// Tartib muhim: AVVAL qo'shiladi, keyin o'chiriladi. Teskari tartibda
// marshrut almashtirilayotgan paytda trafik uchun marshrutsiz oyna
// ochiladi.
func (d *Device) SetRoutes(desired []netip.Prefix) (RouteDiff, error) {
	normalized, err := normalizeRoutes(desired)
	if err != nil {
		return RouteDiff{}, err
	}

	d.routesMx.Lock()
	defer d.routesMx.Unlock()

	current, err := d.currentRoutes()
	if err != nil {
		return RouteDiff{}, err
	}

	plan := planRoutes(current, normalized)
	if plan.Empty() {
		d.applied = normalized
		return plan, nil
	}

	// Qisman muvaffaqiyat mumkin: bitta marshrut qo'shilmasa ham
	// qolganlari qo'yiladi. Shuning uchun HAQIQATDA bajarilganini
	// alohida yig'amiz — `applied` yolg'on gapirmasligi kerak.
	var (
		errs    []error
		added   []netip.Prefix
		removed []netip.Prefix
	)

	for _, prefix := range plan.Added {
		if err := addRouteFor(d.name, prefix); err != nil {
			errs = append(errs, err)
			continue
		}
		added = append(added, prefix)
	}

	for _, prefix := range plan.Removed {
		if err := delRouteFor(d.name, prefix); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, prefix)
	}

	d.applied = applyResult(current, added, removed)

	return RouteDiff{Added: added, Removed: removed}, errors.Join(errs...)
}

// Routes — oxirgi marta muvaffaqiyatli qo'llangan marshrutlar.
func (d *Device) Routes() []netip.Prefix {
	d.routesMx.Lock()
	defer d.routesMx.Unlock()

	return slices.Clone(d.applied)
}

// currentRoutes yadrodan haqiqiy holatni oladi. Platforma buni qo'llab-
// quvvatlamasa — o'zimiz qo'ygan ro'yxatga qaytamiz.
//
// Chaqiruvchi routesMx ni ushlab turgan bo'lishi kerak.
func (d *Device) currentRoutes() ([]netip.Prefix, error) {
	kernel, err := listRoutes(d.name)
	if errors.Is(err, ErrRoutesNotEnumerable) {
		return slices.Clone(d.applied), nil
	}
	if err != nil {
		return nil, err
	}

	return normalizeRoutes(kernel)
}

// planRoutes ikki to'plamni solishtiradi.
func planRoutes(current, desired []netip.Prefix) RouteDiff {
	have := make(map[netip.Prefix]struct{}, len(current))
	for _, prefix := range current {
		have[prefix] = struct{}{}
	}

	want := make(map[netip.Prefix]struct{}, len(desired))
	for _, prefix := range desired {
		want[prefix] = struct{}{}
	}

	var diff RouteDiff
	for _, prefix := range desired {
		if _, ok := have[prefix]; !ok {
			diff.Added = append(diff.Added, prefix)
		}
	}
	for _, prefix := range current {
		if _, ok := want[prefix]; !ok {
			diff.Removed = append(diff.Removed, prefix)
		}
	}
	return diff
}

// applyResult qisman bajarilgandan keyingi haqiqiy holatni hisoblaydi.
func applyResult(current, added, removed []netip.Prefix) []netip.Prefix {
	gone := make(map[netip.Prefix]struct{}, len(removed))
	for _, prefix := range removed {
		gone[prefix] = struct{}{}
	}

	result := make([]netip.Prefix, 0, len(current)+len(added))
	for _, prefix := range current {
		if _, dropped := gone[prefix]; !dropped {
			result = append(result, prefix)
		}
	}
	result = append(result, added...)

	slices.SortFunc(result, comparePrefixes)
	return result
}

// normalizeRoutes prefikslarni tekshiradi, host bitlarini tozalaydi,
// takrorlarni olib tashlaydi va tartiblaydi.
//
// Tartiblash solishtirishni barqaror qiladi: bir xil to'plam har doim
// bir xil ko'rinishga keladi va diff "o'zgardi" deb yolg'on aytmaydi.
func normalizeRoutes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(prefixes))

	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("tun: marshrut yaroqsiz: %v", prefix)
		}
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("%w: %v", ErrNotIPv6, prefix)
		}
		result = append(result, prefix.Masked())
	}

	slices.SortFunc(result, comparePrefixes)
	return slices.Compact(result), nil
}

func comparePrefixes(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

func joinPrefixes(prefixes []netip.Prefix) string {
	parts := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		parts[i] = prefix.String()
	}
	return strings.Join(parts, ",")
}
