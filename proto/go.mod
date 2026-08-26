// Yagona kontrakt moduli: generatsiya qilingan protobuf kodi shu yerda
// yashaydi, chunki uni core-server, daemon va control — uchalasi ham
// ishlatadi. Uni bitta modul ichida saqlash ularni bir-biriga
// bog'lamasdan umumiy tiplarni bo'lishish imkonini beradi.
module github.com/freco-dev/cc01/proto

go 1.25.0

require (
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
