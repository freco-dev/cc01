package server

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NotLeaderReason — "bu node lider emas" xatosining mashina o'qiy
// oladigan sababi.
//
// Klient uni xato MATNIDAN emas, shu yerdan biladi: matn tarjima
// qilinishi yoki qayta yozilishi mumkin, sabab esa shartnomaning
// bir qismi.
const NotLeaderReason = "NOT_LEADER"

// notLeaderDomain — sabab qaysi tizimga tegishli (Google AIP-193).
const notLeaderDomain = "cc01.control"

// notLeaderStatus klientga "boshqa nodega murojaat qil" deb aytadi.
//
// Kod `Unavailable`: bu vaqtinchalik holat va so'rovni takrorlash
// mumkin. `FailedPrecondition` bo'lganda gRPC klientlari uni
// takrorlanmaydigan deb hisoblardi.
//
// ⚠️ Liderning Raft manzili ATAYLAB yuborilmaydi. U Raft transporti
// porti (masalan :7000), klient esa gRPC portiga (masalan :8443)
// ulanadi — ya'ni o'sha manzilni klientga bersak, u ulanolmaydigan
// joyga borardi. Klient buning o'rniga o'ziga berilgan CP manzillari
// ro'yxatini aylanib chiqadi.
func notLeaderStatus() error {
	st := status.New(codes.Unavailable,
		"bu node lider emas; boshqa CP manziliga murojaat qiling")

	detail, wrapErr := st.WithDetails(&errdetails.ErrorInfo{
		Reason: NotLeaderReason,
		Domain: notLeaderDomain,
	})
	if wrapErr != nil {
		// Tafsilot qo'shilmasa ham xato o'zi to'g'ri — klient
		// shunchaki keyingi manzilga o'tolmaydi.
		return st.Err()
	}

	return detail.Err()
}
