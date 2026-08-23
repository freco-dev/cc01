#!/bin/sh
set -e

# Guruh va soket papkasi. sysusers/tmpfiles fayllari o'rnatildi,
# lekin ular keyingi yuklanishgacha qo'llanmaydi — hozir ham
# qo'llaymiz, shunda o'rnatishdan keyin darhol ishlaydi.
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/cc01.conf >/dev/null 2>&1 || true
elif ! getent group cc01 >/dev/null 2>&1; then
    groupadd --system cc01 >/dev/null 2>&1 || true
fi

if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/cc01.conf >/dev/null 2>&1 || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Demon ATAYLAB avtomatik yoqilmaydi: unga node kaliti va CP manzili
# kerak, ular esa /etc/cc01/cc01d.env da hali bo'sh. Kalitsiz ishga
# tushirish faqat xato logini beradi.
cat <<'MSG'

cc01 o'rnatildi. Keyingi qadamlar:

  1. Kalit yarating:
       sudo sh -c 'echo "CC01_PRIVATE_KEY=$(cc01d -genkey)" >> /etc/cc01/cc01d.env'

  2. Control Plane manzilini kiriting:
       sudo editor /etc/cc01/cc01d.env

  3. Ishga tushiring:
       sudo systemctl enable --now cc01d

  4. CLI dan foydalanish uchun o'zingizni guruhga qo'shing
     (keyin qayta login qiling):
       sudo usermod -aG cc01 "$USER"

MSG

exit 0
