#!/usr/bin/env bash
# cc01 — AP ↔ Edge mTLS uchun DEV sertifikatlari (DEV_SPEC A-S5, S-11).
#
#   make dev-certs            → .dev-certs/ (bor bo'lsa tegmaydi)
#   make dev-certs FORCE=1    → qaytadan yaratadi
#
# Natija (hammasi PEM, kalitlar PKCS#8, ECDSA P-256):
#
#   ca.pem / ca.key               ichki CA — ikkala tomon FAQAT shunga ishonadi
#   ap.pem / ap.key               access-server ichki listeneri (SAN: localhost, 127.0.0.1)
#   edge.pem / edge.key           edge klienti,     CN=edge-dev,     clientAuth
#   operator.pem / operator.key   operator (curl),  CN=operator-dev, clientAuth
#   rogue-ca.pem                  BEGONA CA — salbiy tekshiruvlar uchun
#   rogue-edge.pem / .key         begona CA imzolagan, lekin CN=edge-dev
#
# ⚠️ Faqat lokal ishlab chiqish uchun. Prod sertifikatlari bu skript bilan
#    YARATILMAYDI: CA kaliti bu yerda shifrlanmagan holda diskda turadi.
#    Fayllar .gitignore da (*.pem, *.key, .dev-certs/).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${CC01_DEV_CERTS:-$ROOT/.dev-certs}"
DAYS=825   # Apple/brauzerlar server sertifikati uchun qabul qiladigan chegara

if [[ -f "$OUT/ca.pem" && "${FORCE:-0}" != "1" ]]; then
  echo "✔ $OUT mavjud — tegilmadi (qayta yaratish: make dev-certs FORCE=1)"
  exit 0
fi

rm -rf "$OUT"
mkdir -p "$OUT"
chmod 700 "$OUT"
cd "$OUT"

# LibreSSL (macOS) va OpenSSL 3 da bir xil ishlaydigan buyruqlar tanlangan:
# `-addext` va `genpkey -algorithm EC` LibreSSL'ning eski versiyalarida yo'q.
key() {
  openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null \
    | openssl pkcs8 -topk8 -nocrypt -out "$1.key"
  chmod 600 "$1.key"
}

# $1=nom  $2=CN  $3=imzolovchi CA (nom)  $4=kengaytmalar (extfile matni)
issue() {
  local name="$1" cn="$2" ca="$3" ext="$4"
  key "$name"
  openssl req -new -key "$name.key" -subj "/O=cc01-dev/CN=$cn" -out "$name.csr" 2>/dev/null
  printf '%s\n' "$ext" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA "$ca.pem" -CAkey "$ca.key" -CAcreateserial \
    -days "$DAYS" -sha256 -extfile "$name.ext" -out "$name.pem" 2>/dev/null
  rm -f "$name.csr" "$name.ext"
}

make_ca() {
  local name="$1" cn="$2"
  key "$name"
  printf '%s\n' \
    "basicConstraints=critical,CA:TRUE,pathlen:0" \
    "keyUsage=critical,keyCertSign,cRLSign" \
    "subjectKeyIdentifier=hash" > "$name.ext"
  openssl req -new -x509 -key "$name.key" -subj "/O=cc01-dev/CN=$cn" \
    -days 3650 -sha256 -extensions v3_ca -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3_ca]\n'; cat "$name.ext") \
    -out "$name.pem" 2>/dev/null
  rm -f "$name.ext"
}

LEAF_COMMON="basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
authorityKeyIdentifier=keyid"

make_ca ca "cc01 dev internal CA"
issue ap "access-server" ca "$LEAF_COMMON
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
issue edge "edge-dev" ca "$LEAF_COMMON
extendedKeyUsage=clientAuth"
issue operator "operator-dev" ca "$LEAF_COMMON
extendedKeyUsage=clientAuth"

make_ca rogue-ca "rogue CA"
issue rogue-edge "edge-dev" rogue-ca "$LEAF_COMMON
extendedKeyUsage=clientAuth"

rm -f ./*.srl
# Begona CA kaliti kerak emas — faqat sertifikati salbiy testlarda ishlatiladi.
rm -f rogue-ca.key

openssl verify -CAfile ca.pem ap.pem edge.pem operator.pem >/dev/null
if openssl verify -CAfile ca.pem rogue-edge.pem >/dev/null 2>&1; then
  echo "✘ rogue-edge.pem ichki CA bilan tasdiqlandi — skript xato" >&2
  exit 1
fi

echo "✔ dev sertifikatlari: $OUT"
echo "  AP:   Internal__Tls__CertPath=$OUT/ap.pem Internal__Tls__KeyPath=$OUT/ap.key"
echo "        Internal__Tls__ClientCaPath=$OUT/ca.pem Internal__Tls__AllowedClients=edge-dev,operator-dev"
echo "  Edge: CC01_ACCESS_TLS_CA=$OUT/ca.pem CC01_ACCESS_TLS_CERT=$OUT/edge.pem CC01_ACCESS_TLS_KEY=$OUT/edge.key"
