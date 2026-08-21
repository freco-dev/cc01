module github.com/freco-dev/cc01/cli-client

go 1.25.0

require github.com/freco-dev/cc01/core-server v0.0.0

// go.work ishlatilmaganda (CI'da modul-po-modul build, `go mod tidy`)
// shu replace kerak — core-server hali versiyalanmagan.
replace github.com/freco-dev/cc01/core-server => ../core-server
