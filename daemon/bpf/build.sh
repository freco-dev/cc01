#!/bin/sh
# XDP dasturini BPF bytecode'ga kompilyatsiya qiladi.
#
# Natija TO'G'RIDAN-TO'G'RI `daemon/xdp/` ga yoziladi — u yerda Go
# uni `//go:embed` bilan ichkariga oladi. Ikkita nusxa saqlansa ular
# ajralib ketishi mumkin va qaysi biri ishlatilayotgani ko'rinmasdi.
#
# Fayl repoga commit qilinadi, shunda demonni qurish uchun clang
# kerak bo'lmaydi.
set -eu

OUT=${OUT:-../xdp/xdp_filter.o}

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  TARGET_ARCH=x86 ;;
    aarch64) TARGET_ARCH=arm64 ;;
    *) echo "qo'llab-quvvatlanmagan arxitektura: $ARCH" >&2; exit 1 ;;
esac

# -O2: verifier optimizatsiya qilinmagan kodni ko'pincha rad etadi
#      (juda ko'p instruksiya, isbotlab bo'lmaydigan tarmoqlanish).
# -g:  BTF ma'lumoti — CO-RE relokatsiyasi uchun shart.
# -target bpf: BPF bytecode chiqarish.
clang -O2 -g -Wall -Werror \
    -target bpf \
    -D__TARGET_ARCH_${TARGET_ARCH} \
    -I/usr/include/${ARCH}-linux-gnu \
    -Iinclude \
    -c xdp_filter.c -o "$OUT"

echo "✔ $OUT ($(stat -c%s "$OUT") bayt)"

# Verifier'ga borishdan oldin bytecode'ning o'zi to'g'riligini
# tekshiramiz: bo'limlar joyidami va BTF bormi.
llvm-objdump -h "$OUT" | grep -qE '\.BTF' \
    || { echo "✘ BTF yo'q — CO-RE ishlamaydi" >&2; exit 1; }
llvm-objdump -h "$OUT" | grep -qE 'xdp' \
    || { echo "✘ xdp bo'limi yo'q" >&2; exit 1; }
