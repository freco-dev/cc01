package ipc

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// DefaultGroup — soket qaysi guruhga tegishli bo'lishi (DEV_SPEC §5.2:
// egasi `root:cc01`).
//
// 0660 ruxsatining o'zi yetarli emas: soket root:root bo'lib qolsa,
// `cc01` guruhidagi foydalanuvchi ham ulana olmaydi va CLI bergan
// "demon guruhiga qo'shiling" maslahati ishlamaydi.
const DefaultGroup = "cc01"

// errGroupMissing — guruh tizimda mavjud emas.
var errGroupMissing = errors.New("guruh topilmadi")

// applyOwnership soketni `group` guruhiga beradi.
//
// Guruh yo'q bo'lsa xato qaytariladi, lekin chaqiruvchi buni halokatli
// deb hisoblamasligi kerak: konteynerda yoki paketsiz o'rnatishda
// guruh bo'lmasligi normal, va demonni shu sababli to'xtatish
// foydalanuvchiga hech qanday foyda keltirmaydi.
func applyOwnership(socket, group string) error {
	if group == "" {
		return nil
	}

	found, err := user.LookupGroup(group)
	if err != nil {
		var unknown user.UnknownGroupError
		if errors.As(err, &unknown) {
			return fmt.Errorf("%w: %s", errGroupMissing, group)
		}
		return fmt.Errorf("guruhni qidirish (%s): %w", group, err)
	}

	gid, err := strconv.Atoi(found.Gid)
	if err != nil {
		return fmt.Errorf("guruh gid (%s): %w", group, err)
	}

	// -1 — egasini o'zgartirmaymiz: demon root sifatida ishlaydi va
	// shunday qolishi kerak.
	if err := os.Chown(socket, -1, gid); err != nil {
		return fmt.Errorf("egalikni o'rnatish (%s): %w", group, err)
	}

	return nil
}
