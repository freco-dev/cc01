module github.com/freco-dev/cc01/daemon

go 1.25.0

require (
	github.com/cilium/ebpf v0.22.0
	github.com/flynn/noise v1.1.0
	github.com/freco-dev/cc01/proto v0.0.0-00010101000000-000000000000
	github.com/pion/stun/v3 v3.1.7
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/crypto v0.55.0
	golang.org/x/net v0.58.0
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/pion/dtls/v3 v3.1.5 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v4 v4.1.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

// Yagona kontrakt moduli — repo ichida, hali versiyalanmagan.
replace github.com/freco-dev/cc01/proto => ../proto
