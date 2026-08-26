package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	"github.com/freco-dev/cc01/control/cluster"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// PinPrefix — sertifikat barmoq izining old qo'shimchasi. Format
// node tomonidagisi bilan bir xil.
const PinPrefix = "sha256/"

// clientPin ulanishdagi klient sertifikatining barmoq izini
// qaytaradi. Sertifikat berilmagan bo'lsa bo'sh satr.
func clientPin(ctx context.Context) string {
	info, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}

	tlsInfo, ok := info.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ""
	}

	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return ""
	}

	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return PinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// authenticate nodeni tanitadi.
//
// Ikki bosqichli model (Tailscale'dagi auth key bilan bir xil g'oya):
//
//	RO'YXATGA OLISH   node hali bog'lanmagan → oldindan kelishilgan
//	                  token talab qilinadi va sertifikat node_id ga
//	                  bog'lanadi
//	KEYINGI ULANISH   bog'lanish bor → AYNAN o'sha sertifikat talab
//	                  qilinadi; token qabul qilinmaydi
//
// Nega token o'zi yetarli emas: u UMUMIY sir, hamma nodeda bir xil.
// Bitta node buzilsa, o'sha token bilan boshqa nodening o'rniga
// o'tib bo'lardi. Sertifikat esa faqat shu nodeda.
//
// Nega token butunlay olib tashlanmaydi: birinchi ulanishda nodeni
// tanitadigan boshqa narsa yo'q. Token endi faqat "yangi node
// qo'shish huquqi" ni bildiradi, mavjud nodening o'rniga o'tish
// huquqini emas.
func (s *Service) authenticate(ctx context.Context, nodeID, token string) error {
	pin := clientPin(ctx)

	existing, bound, err := s.identities.Identity(ctx, nodeID)
	if err != nil {
		return status.Errorf(codes.Internal, "bog'lanishni o'qish: %v", err)
	}

	if bound {
		if pin == "" {
			return status.Error(codes.Unauthenticated,
				"node sertifikat bilan tanitilishi kerak")
		}
		if subtle.ConstantTimeCompare([]byte(pin), []byte(existing)) != 1 {
			// Bu jiddiy hodisa: yo node kalitini yo'qotgan, yo
			// kimdir uning o'rniga o'tmoqchi. Ikkalasi ham
			// operator aralashuvini talab qiladi.
			s.log.Warn("node BOSHQA sertifikat bilan keldi",
				"node", shortID(nodeID), "kutilgan", existing, "olingan", pin)
			return status.Error(codes.PermissionDenied,
				"node sertifikati bog'langanidan farq qiladi")
		}
		return nil
	}

	// Hali bog'lanmagan — ro'yxatga olish.
	if err := s.authorize(token); err != nil {
		return err
	}

	if pin == "" {
		// Sertifikatsiz ham ro'yxatdan o'tishga ruxsat beramiz,
		// lekin bu holatda himoya faqat tokenga tayanadi.
		s.log.Warn("node sertifikatsiz ro'yxatdan o'tdi — himoya faqat tokenga tayanadi",
			"node", shortID(nodeID))
		return nil
	}

	if err := s.identities.Bind(ctx, nodeID, pin); err != nil {
		if errors.Is(err, cluster.ErrIdentityMismatch) {
			return status.Error(codes.PermissionDenied,
				"node sertifikati bog'langanidan farq qiladi")
		}

		var notLeader *cluster.ErrNotLeader
		if errors.As(err, &notLeader) {
			return notLeaderStatus()
		}
		return status.Errorf(codes.Internal, "bog'lanishni yozish: %v", err)
	}

	s.log.Info("node sertifikatga bog'landi", "node", shortID(nodeID), "pin", pin)
	return nil
}

// shortID node identifikatorining qisqartirilgan ko'rinishi.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
