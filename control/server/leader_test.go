package server

import (
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Bu shartnoma daemon klienti bilan bo'linadi
// (`daemon/control.isNotLeader`). Ikki modul alohida, ya'ni
// kompilyator ularni bog'lab turmaydi — shuning uchun shartnoma
// shu yerda oshkora qulflanadi.
func TestNotLeaderStatus_CarriesMachineReadableReason(t *testing.T) {
	st := status.Convert(notLeaderStatus())

	// Kod takrorlanadigan bo'lishi shart: klient boshqa nodega
	// murojaat qiladi.
	if st.Code() != codes.Unavailable {
		t.Errorf("kod %s, Unavailable kutilgan edi", st.Code())
	}

	var found bool
	for _, detail := range st.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}
		found = true

		if info.GetReason() != NotLeaderReason {
			t.Errorf("sabab %q, %q kutilgan edi", info.GetReason(), NotLeaderReason)
		}
		if info.GetDomain() != notLeaderDomain {
			t.Errorf("domen %q", info.GetDomain())
		}
	}

	if !found {
		t.Fatal("ErrorInfo tafsiloti yo'q — klient sababni bilolmaydi")
	}
}

// Sabab satri daemon klientidagi nusxasi bilan bir xil bo'lishi
// shart. Ikkalasi ham shu qiymatga qattiq bog'langan.
func TestNotLeaderReason_IsStable(t *testing.T) {
	if NotLeaderReason != "NOT_LEADER" {
		t.Errorf("sabab o'zgardi: %q. daemon/control dagi nusxasi ham "+
			"o'zgartirilishi kerak, aks holda klient liderni topolmaydi",
			NotLeaderReason)
	}
}
