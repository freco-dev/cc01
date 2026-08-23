#!/bin/sh
# Paketni toza konteynerda o'rnatib tekshiradi.
#
# Nega konteyner: paket qanday muhitga tushishini faqat shu yerda
# ko'rish mumkin — host mashinada `dpkg -i` qilish uni ifloslantiradi
# va natija oldingi holatga bog'liq bo'lib qoladi.
#
# systemd konteynerda yuklanmaydi, shuning uchun unit fayli
# `systemd-analyze verify` bilan tekshiriladi: u sintaksis va
# noma'lum direktivalarni topadi.

set -eu

DOCKER="docker --context ${DOCKER_CONTEXT:-desktop-linux}"
ARCH=$(uname -m)

case "$ARCH" in
    arm64|aarch64) DEB_ARCH=arm64 ;;
    x86_64|amd64)  DEB_ARCH=amd64 ;;
    *) echo "✘ qo'llab-quvvatlanmagan arxitektura: $ARCH"; exit 1 ;;
esac

DEB=$(ls dist/cc01_*_${DEB_ARCH}.deb 2>/dev/null | head -1)
if [ -z "$DEB" ]; then
    echo "✘ paket topilmadi. Avval quring: make package"
    exit 1
fi

echo "→ tekshirilmoqda: $DEB"
echo

$DOCKER run --rm -v "$PWD":/src -w /src debian:trixie-slim sh -euc "
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq systemd iproute2 >/dev/null

    echo '── o'\''rnatish ──'
    dpkg -i '$DEB' 2>&1 | grep -v '^Selecting\|^Preparing\|^Unpacking\|^Setting up' || true

    echo
    echo '── fayllar joyidami ──'
    for f in /usr/bin/cc01d /usr/bin/cc01 /usr/lib/cc01/cc01-cleanup \\
             /lib/systemd/system/cc01d.service /etc/cc01/cc01d.env \\
             /usr/lib/sysusers.d/cc01.conf /usr/lib/tmpfiles.d/cc01.conf; do
        if [ -e \"\$f\" ]; then printf '  ✔ %s\n' \"\$f\"; else printf '  ✘ %s YO'\''Q\n' \"\$f\"; exit 1; fi
    done

    echo
    echo '── konfiguratsiya faqat root uchunmi ──'
    mode=\$(stat -c '%a' /etc/cc01/cc01d.env)
    if [ \"\$mode\" = '600' ]; then
        printf '  ✔ /etc/cc01/cc01d.env = %s\n' \"\$mode\"
    else
        printf '  ✘ /etc/cc01/cc01d.env = %s, 600 kutilgan (unda node kaliti bo'\''ladi)\n' \"\$mode\"; exit 1
    fi

    echo
    echo '── cc01 guruhi yaratildimi ──'
    if getent group cc01 >/dev/null; then
        printf '  ✔ %s\n' \"\$(getent group cc01)\"
    else
        echo '  ✘ guruh yaratilmagan'; exit 1
    fi

    echo
    echo '── systemd unit fayli to'\''g'\''rimi ──'
    if systemd-analyze verify /lib/systemd/system/cc01d.service 2>&1 | grep -v '^$'; then
        echo '  ⚠ yuqoridagi ogohlantirishlarga qarang'
    else
        echo '  ✔ ogohlantirishsiz'
    fi

    echo
    echo '── binarlar ishlaydimi ──'
    printf '  cc01 version:  '; cc01 version
    printf '  cc01d -genkey: '; cc01d -genkey 2>/dev/null | head -c 12; echo '…'

    echo
    echo '── demon ishlamayotganda CLI to'\''g'\''ri xato beradimi ──'
    set +e
    output=\$(cc01 status 2>&1); code=\$?
    set -e
    if [ \"\$code\" -eq 10 ]; then
        printf '  ✔ chiqish kodi 10 (demon ishlamayapti)\n'
    else
        printf '  ✘ chiqish kodi %s, 10 kutilgan edi: %s\n' \"\$code\" \"\$output\"; exit 1
    fi

    echo
    echo '── doctor demonsiz ham javob beradimi ──'
    cc01 doctor | sed 's/^/  /'

    echo
    echo '── cleanup skripti xatosiz ishlaydimi ──'
    /usr/lib/cc01/cc01-cleanup && echo '  ✔ cc01-cleanup'

    echo
    echo '── o'\''chirish ortida nima qoldiradi ──'
    dpkg -r cc01 >/dev/null 2>&1
    for f in /usr/bin/cc01d /lib/systemd/system/cc01d.service; do
        if [ -e \"\$f\" ]; then printf '  ✘ %s qoldi\n' \"\$f\"; exit 1; fi
    done
    echo '  ✔ binarlar va unit olib tashlandi'
    if [ -e /etc/cc01/cc01d.env ]; then
        echo '  ✔ konfiguratsiya saqlandi (unda node kaliti bor)'
    fi
"

echo
echo "✔ paket tekshiruvi o'tdi"
