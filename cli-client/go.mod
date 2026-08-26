module github.com/freco-dev/cc01/cli-client

go 1.25.0

require (
	github.com/freco-dev/cc01/core-server v0.0.0
	github.com/freco-dev/cc01/proto v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.1 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

// go.work ishlatilmaganda (CI'da modul-po-modul build, `go mod tidy`)
// shu replace kerak — core-server hali versiyalanmagan.
replace github.com/freco-dev/cc01/core-server => ../core-server

// Yagona kontrakt moduli — repo ichida, hali versiyalanmagan.
replace github.com/freco-dev/cc01/proto => ../proto
