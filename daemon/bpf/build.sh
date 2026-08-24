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

XDP_OUT=${XDP_OUT:-../xdp/xdp_filter.o}
TC_OUT=${TC_OUT:-../tcpolicy/tc_policy.o}

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
compile() {
    src=$1; out=$2
    clang -O2 -g -Wall -Werror \
        -target bpf \
        -D__TARGET_ARCH_${TARGET_ARCH} \
        -I/usr/include/${ARCH}-linux-gnu \
        -Iinclude \
        -c "$src" -o "$out"
    echo "✔ $out ($(stat -c%s "$out") bayt)"
}

mkdir -p "$(dirname "$TC_OUT")"
compile xdp_filter.c "$XDP_OUT"
compile tc_policy.c "$TC_OUT"

OUT=$XDP_OUT

# Verifier'ga borishdan oldin bytecode'ning o'zi to'g'riligini
# tekshiramiz: bo'limlar joyidami va BTF bormi.
llvm-objdump -h "$OUT" | grep -qE '\.BTF' \
    || { echo "✘ BTF yo'q — CO-RE ishlamaydi" >&2; exit 1; }
llvm-objdump -h "$OUT" | grep -qE 'xdp' \
    || { echo "✘ xdp bo'limi yo'q" >&2; exit 1; }

llvm-objdump -h "$TC_OUT" | grep -qE '\.BTF' \
    || { echo "✘ tc: BTF yo'q" >&2; exit 1; }
llvm-objdump -h "$TC_OUT" | grep -qE '^ *[0-9]+ tc' \
    || { echo "✘ tc bo'limi yo'q" >&2; exit 1; }
