package main

import (
	"github.com/freco-dev/cc01/daemon/ipc"
	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
)

// localChecks demon ishlamayotganda mahalliy tekshiruvlarni bajaradi.
//
// `doctor` ning butun ma'nosi shu: demon ishlamayotganda ham u NIMA
// UCHUN ishlamayotganini aytishi kerak.
func localChecks() []*cc01v1.Check {
	return ipc.RunChecks(nil)
}
