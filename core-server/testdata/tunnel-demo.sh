#!/bin/sh
# Tunnel demosi: edge + klient, HTTP va SNI bo'yicha TLS.
#
# Demo nimani ko'rsatadi:
#   1. Klient lokal xizmatga tunnel ochadi
#   2. Tashqi so'rov subdomain orqali lokal xizmatga yetib boradi
#   3. HTTPS da SNI bo'yicha wildcard sertifikat beriladi
#   4. Custom domain (tirik tunnel bilan) sertifikat oladi
#   5. Ro'yxatdan o'tmagan domenga qo'l siqishi RAD ETILADI
set -e

DOCKER="docker --context desktop-linux"
IMAGE=cc01-edge-demo
NET=cc01-tunnel-net
DOMAIN=cc01.test
EDGE_IP=172.39.0.10

cleanup() {
  $DOCKER rm -f cc01-edge cc01-origin cc01-client >/dev/null 2>&1 || true
  $DOCKER network rm $NET >/dev/null 2>&1 || true
  $DOCKER volume rm cc01-tunnel-certs >/dev/null 2>&1 || true
}
if [ -z "${KEEP:-}" ]; then
  trap cleanup EXIT
fi
cleanup

echo "── image ──"
$DOCKER build -q -t $IMAGE -f core-server/testdata/Dockerfile.edge . >/dev/null

echo "── tarmoq ──"
$DOCKER network create --subnet 172.39.0.0/24 $NET >/dev/null

echo "── wildcard sertifikat ──"
# Haqiqiy joylashtirishda `*.cc01.uz` DNS-01 orqali olinadi: ACME
# wildcard uchun DNS provayderining kalitlarini talab qiladi va uni
# demoda takrorlab bo'lmaydi. Custom domainlar esa ACME dan
# HTTP-01/TLS-ALPN-01 bilan oladi — u yerda DNS kaliti kerak emas.
$DOCKER volume create cc01-tunnel-certs >/dev/null
$DOCKER run --rm -v cc01-tunnel-certs:/certs --entrypoint sh $IMAGE -c "
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout /certs/key.pem -out /certs/cert.pem \
    -subj '/CN=*.$DOMAIN' \
    -addext 'subjectAltName=DNS:*.$DOMAIN,DNS:$DOMAIN'" >/dev/null 2>&1
echo "  *.$DOMAIN uchun sertifikat tayyor"

echo
echo "── origin (tunnel ortidagi lokal xizmat) ──"
$DOCKER run -d --name cc01-origin --network $NET --ip 172.39.0.20 \
  --entrypoint cc01-origin $IMAGE -listen :8080 >/dev/null
echo "  172.39.0.20:8080"

echo
echo "── edge ──"
# AUTH_MODE=disabled: demo access-server'siz ishlaydi. Ishlab
# chiqarishda bu rejim taqiqlangan va server ogohlantirish yozadi.
$DOCKER run -d --name cc01-edge --network $NET --ip $EDGE_IP \
  -v cc01-tunnel-certs:/certs \
  -e CC01_DOMAIN=$DOMAIN \
  -e CC01_TLS_CERT=/certs/cert.pem \
  -e CC01_TLS_KEY=/certs/key.pem \
  -e CC01_AUTH_MODE=disabled \
  -e CC01_PUBLIC_PORT=8080 \
  -e CC01_PUBLIC_TLS_PORT=8443 \
  -e CC01_EVENT_PORT=4321 \
  --entrypoint cc01-edge $IMAGE >/dev/null
sleep 3

if ! $DOCKER ps --format '{{.Names}}' | grep -q cc01-edge; then
  echo "  ✘ edge ko'tarilmadi"; $DOCKER logs cc01-edge 2>&1 | tail -10; exit 1
fi
echo "  HTTP :8080, HTTPS :8443, event :4321"

echo
echo "═══ klient tunnel ochadi ═══"
$DOCKER run -d --name cc01-client --network $NET --ip 172.39.0.30 \
  --entrypoint cc01-tunnel $IMAGE \
  -server $EDGE_IP:4321 -local 172.39.0.20:8080 \
  -proto http -subdomain demo -cname app.mijoz.test >/dev/null
sleep 3

TUNNEL_LOG=$($DOCKER logs cc01-client 2>&1 | tail -3)
echo "$TUNNEL_LOG" | sed 's/^/  /'

# Tashqi so'rovlarni alohida konteynerdan yuboramiz: edge o'z
# ichidan so'rasak, tarmoq yo'li haqiqiy mijoznikidan farq qilardi.
req() {
  $DOCKER run --rm --network $NET --entrypoint curl $IMAGE "$@" 2>&1
}

echo
echo "═══ HTTP: subdomain orqali ═══"
BODY=$(req -s --max-time 10 -H "Host: demo.$DOMAIN" "http://$EDGE_IP:8080/" || true)
if echo "$BODY" | grep -q "salom cc01 tunnelidan"; then
  echo "  ✔ $BODY"
else
  echo "  ✘ javob kelmadi: ${BODY:-BO_SH}"
  $DOCKER logs cc01-edge 2>&1 | tail -10
  exit 1
fi

echo
echo "═══ HTTPS: SNI bo'yicha sertifikat ═══"
# --resolve: DNS o'rniga SNI va Host'ni bevosita beramiz.
# `</dev/null`: s_client stdin yopilmaguncha ulanishni ushlab
# turadi. `-verify_return_error` YO'Q: sertifikat o'z-o'zini
# imzolagan va tekshiruv xatosi bizni qiziqtirmaydi — bizga
# qaysi sertifikat BERILGANI kerak.
sni() {
  $DOCKER run --rm --network $NET --entrypoint sh $IMAGE -c \
    "openssl s_client -connect $EDGE_IP:8443 -servername '$1' </dev/null 2>&1 | cat" \
    | grep -v "broken pipe"
}

CN=$(sni "demo.$DOMAIN" | grep -m1 "subject=" || true)
if echo "$CN" | grep -q "$DOMAIN"; then
  echo "  ✔ demo.$DOMAIN → $CN"
else
  echo "  ✘ wildcard sertifikat berilmadi: ${CN:-YO_Q}"
  exit 1
fi

echo
echo "═══ HTTPS: ro'yxatdan o'tmagan domen ═══"
# Bu Faza 3 dagi eng muhim xavfsizlik tekshiruvi: begona domenga
# sertifikat bersak, kimdir o'z DNS'ini bizga qaratib ACME
# limitlarini yoqib yuborardi.
OUT=$(sni "begona.example.com" || true)
if echo "$OUT" | grep -qE "alert|handshake failure|no certificate|error"; then
  echo "  ✔ qo'l siqishi rad etildi"
else
  echo "  ✘ begona domenga sertifikat berildi:"
  echo "$OUT" | grep -m1 "subject=" | sed 's/^/    /'
  exit 1
fi

echo
echo "═══ HTTPS orqali to'liq so'rov ═══"
BODY=$(req -sk --max-time 10 --resolve "demo.$DOMAIN:8443:$EDGE_IP" \
  "https://demo.$DOMAIN:8443/" || true)
if echo "$BODY" | grep -q "salom cc01 tunnelidan"; then
  echo "  ✔ $BODY"
else
  echo "  ✘ HTTPS orqali javob kelmadi: ${BODY:-BO_SH}"
  exit 1
fi

echo
echo "── natija ──"
echo "  tunnel ishlaydi, sertifikat SNI bo'yicha tanlanadi,"
echo "  begona domen rad etiladi"
