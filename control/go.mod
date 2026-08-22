module github.com/freco-dev/cc01/control

go 1.25.0

// Yagona kontrakt moduli — repo ichida, hali versiyalanmagan.
replace github.com/freco-dev/cc01/proto => ../proto

require (
	github.com/freco-dev/cc01/daemon v0.0.0-00010101000000-000000000000
	github.com/freco-dev/cc01/proto v0.0.0-00010101000000-000000000000
	github.com/pion/stun/v3 v3.1.7
	google.golang.org/grpc v1.83.1
)

require (
	github.com/flynn/noise v1.1.0 // indirect
	github.com/pion/dtls/v3 v3.1.5 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v4 v4.1.0 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/freco-dev/cc01/daemon => ../daemon
