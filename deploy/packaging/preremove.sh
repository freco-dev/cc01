#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop cc01d >/dev/null 2>&1 || true
    systemctl disable cc01d >/dev/null 2>&1 || true
fi

# Demon to'xtaganda o'zi tozalaydi, lekin u allaqachon o'lgan bo'lishi
# mumkin — ortda qolgan marshrut va qoidalarni olib tashlaymiz.
if [ -x /usr/lib/cc01/cc01-cleanup ]; then
    /usr/lib/cc01/cc01-cleanup || true
fi

exit 0
