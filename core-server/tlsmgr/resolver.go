// Package tlsmgr edge uchun TLS sertifikatlarini boshqaradi
// (DEV_SPEC §2.1 `internal/edge/tlsmgr`, Faza 3).
package tlsmgr

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
)

// ErrUnknownName — bu nom uchun sertifikat berilmaydi.
//
// TLS qo'l siqishi shu bilan uziladi va bu ATAYLAB: noto'g'ri
// sertifikatni ko'rsatgandan ko'ra ulanishni rad etgan ma'qul.
// Brauzer bunda aniq xato ko'rsatadi, aralashuv esa yashirin
// qolmaydi.
var ErrUnknownName = errors.New("tlsmgr: bu nom uchun sertifikat yo'q")

// Issuer — talab bo'yicha sertifikat chiqaruvchi (ACME).
type Issuer interface {
	// Certificate nom uchun sertifikat qaytaradi.
	//
	// ⚠️ HAR BIR qo'l siqishida chaqiriladi, ya'ni takroriy
	// chaqiruv tez bo'lishi shart — implementatsiya o'zi
	// keshlashi kerak.
	//
	// Resolver ATAYLAB keshlamaydi: chiqaruvchi sertifikatni fon
	// rejimida yangilaydi va bizdagi nusxa eskirib qolardi. Bundan
	// tashqari keshsiz ruxsat tekshiruvi har safar qaytadan
	// bajariladi, ya'ni tunnel yopilishi bilan sertifikat berish
	// darhol to'xtaydi.
	Certificate(ctx context.Context, name string) (*tls.Certificate, error)
}

// KnownFunc — bu nom bizga TEGISHLIMI.
//
// ⚠️ ACME dagi eng jiddiy suiiste'mol yo'li shu: kimdir o'z
// domenining DNS'ini bizga qaratsa va biz har bir SNI uchun
// sertifikat chiqaraversak, Let's Encrypt limitlariga urilib,
// HAQIQIY mijozlarga sertifikat chiqara olmay qolardik. Shuning
// uchun custom domain faqat ro'yxatdan o'tgan bo'lsa xizmat
// qilinadi.
type KnownFunc func(name string) bool

// Options — resolver sozlamalari.
type Options struct {
	// Domain — asosiy domen ("cc01.uz"). Uning subdomainlariga
	// wildcard sertifikat beriladi.
	Domain string

	// Wildcard — `*.Domain` uchun sertifikat. Bo'lmasa subdomainlar
	// ham Issuer orqali oladi.
	Wildcard *tls.Certificate

	// Apex — `Domain` ning o'zi uchun sertifikat.
	//
	// Alohida kerak: `*.cc01.uz` wildcard'i `cc01.uz` ni QOPLAMAYDI
	// (RFC 6125), ya'ni apex uchun wildcard'ni ishlatsak brauzer
	// nomni mos kelmagan deb rad etardi.
	Apex *tls.Certificate

	// Known — custom domain ro'yxatdan o'tganmi. nil bo'lsa custom
	// domainlarga umuman xizmat qilinmaydi.
	Known KnownFunc

	// Issuer — talab bo'yicha chiqaruvchi. nil bo'lsa faqat
	// oldindan berilgan sertifikatlar ishlatiladi.
	Issuer Issuer
}

// Resolver SNI nomiga qarab sertifikat tanlaydi.
type Resolver struct {
	domain   string
	suffix   string
	wildcard *tls.Certificate
	apex     *tls.Certificate
	known    KnownFunc
	issuer   Issuer
}

func New(opts Options) (*Resolver, error) {
	domain := strings.ToLower(strings.TrimSpace(opts.Domain))
	if domain == "" {
		return nil, errors.New("tlsmgr: domen berilmagan")
	}
	if opts.Wildcard == nil && opts.Issuer == nil {
		return nil, errors.New(
			"tlsmgr: na wildcard sertifikat, na chiqaruvchi berilgan — " +
				"hech bir nomga xizmat qilinmasdi")
	}

	return &Resolver{
		domain:   domain,
		suffix:   "." + domain,
		wildcard: opts.Wildcard,
		apex:     opts.Apex,
		known:    opts.Known,
		issuer:   opts.Issuer,
	}, nil
}

// GetCertificate — `tls.Config.GetCertificate` uchun.
func (r *Resolver) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))

	// SNI siz ulanish RAD ETILADI. Zamonaviy klientlar uni doim
	// yuboradi; yubormaganiga wildcard bersak, qaysi tunnelga
	// tegishli ekanini bilmasdan sertifikat ko'rsatgan bo'lardik.
	if name == "" {
		return nil, fmt.Errorf("%w: SNI yo'q", ErrUnknownName)
	}
	if err := validName(name); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownName, err)
	}

	ctx := hello.Context()

	switch {
	case name == r.domain:
		if r.apex != nil {
			return r.apex, nil
		}
		return r.issue(ctx, name)

	case r.isSubdomain(name):
		if r.wildcard != nil {
			return r.wildcard, nil
		}
		return r.issue(ctx, name)

	default:
		// Custom domain: faqat ro'yxatdan o'tgan bo'lsa.
		if r.known == nil || !r.known(name) {
			return nil, fmt.Errorf("%w: %s ro'yxatdan o'tmagan", ErrUnknownName, name)
		}
		return r.issue(ctx, name)
	}
}

// isSubdomain — nom `*.domain` wildcard'i ostidami.
//
// Wildcard FAQAT bitta yorliqni qoplaydi (RFC 6125 §6.4.3):
// `*.cc01.uz` `a.cc01.uz` ga mos keladi, `a.b.cc01.uz` ga esa
// YO'Q. Buni e'tiborsiz qoldirsak, chuqurroq nomga wildcard
// bergan bo'lardik va brauzer uni rad etardi.
func (r *Resolver) isSubdomain(name string) bool {
	label, found := strings.CutSuffix(name, r.suffix)
	return found && label != "" && !strings.Contains(label, ".")
}

func (r *Resolver) issue(ctx context.Context, name string) (*tls.Certificate, error) {
	if r.issuer == nil {
		return nil, fmt.Errorf("%w: %s (chiqaruvchi sozlanmagan)", ErrUnknownName, name)
	}

	cert, err := r.issuer.Certificate(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("tlsmgr: %s uchun sertifikat: %w", name, err)
	}
	if cert == nil {
		return nil, fmt.Errorf("%w: %s (chiqaruvchi bo'sh qaytardi)", ErrUnknownName, name)
	}

	return cert, nil
}

// validName SNI dagi nomni tekshiradi.
//
// Chiqaruvchiga murojaatdan OLDIN turadi: yaroqsiz nomni ACME ga
// yuborish behuda va u yerda kutilmagan xatolarga sabab bo'lardi.
func validName(name string) error {
	if len(name) > 253 {
		return errors.New("nom juda uzun")
	}

	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return errors.New("bo'sh yorliq")
		}
		if len(label) > 63 {
			return errors.New("yorliq juda uzun")
		}
		for _, char := range label {
			switch {
			case char >= 'a' && char <= 'z',
				char >= '0' && char <= '9',
				char == '-':
			default:
				return fmt.Errorf("yaroqsiz belgi: %q", char)
			}
		}
	}
	return nil
}
