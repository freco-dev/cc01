#!/usr/bin/env bash
# Tarif demosi: AP + edge + klient, hammasi lokal jarayon (DEV_SPEC §8).
#
# Demo nimani isbotlaydi:
#   1. Tarif o'zgarishi OCHIQ tunnelga 60 s dan tez yetib boradi
#      (o'lchanadi: `make ap-set-plan` → edge'dagi `[tunnel-limits]`).
#   2. Operator API public portda Host sarlavhasini soxtalashtirib
#      chaqirilsa 404 (A-S19) — gRPC ham.
#   3. AP o'chsa ochiq tunnel ishlashda davom etadi (fail-static),
#      edge `[tunnel-renew-failed]` yozadi va qayta urinadi.
#   4. Token bekor qilinsa ochiq tunnel yopiladi: klient TOKEN_REVOKED
#      bilan 1 kodi bilan chiqadi, edge registridan o'chadi.
#   5. (MTLS=1, sukut) AP ↔ Edge kanali mTLS (A-S5, S-11): edge va operator
#      ichki CA sertifikati bilan ulanadi; sertifikatsiz yoki begona CA
#      imzolagan sertifikat bilan ulanish TLS darajasida rad etiladi.
#      MTLS=0 — eski h2c rejimi (faqat loopback'da ruxsat).
#   6. Usage: tunnel trafigi edge'da sanaladi va GET /v1/usage da
#      ko'rinadi; AP o'chiq paytdagi trafik navbatda kutib, AP qaytgach
#      yetib boradi (CC01_USAGE_INTERVAL=10s — demoni tezlashtirish uchun).
#
# Talablar: Go, .NET SDK, curl, perl, openssl, Docker (faqat dev Postgres uchun).
# Hamma narsa loopback'da; portlarni muhit o'zgaruvchilari bilan
# almashtirish mumkin (pastda). KEEP=1 — vaqtinchalik papka qoldiriladi.
#
# ⚠️ Dev bazasida (cc01_access) har ishga tushishda yangi sinov tenanti
#    qoladi: email va subdomain noyob, boshqa ma'lumotlarga tegmaydi.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DOCKER_CONTEXT=${DOCKER_CONTEXT:-desktop-linux}

# Demo FAQAT lokal dev bazasiga yozadi. Shell'dan meros qolgan ulanish
# satrlari (staging uchun eksport qilingan CC01_ACCESS_DB yoki
# ConnectionStrings__Access) migratsiyani ham, AP yozuvlarini ham boshqa
# bazaga yuborardi — audit tekshiruvi esa baribir lokal konteynerdan
# o'qiydi. .NET konfiguratsiya kalitlari katta-kichik harfni farqlamaydi va
# ASPNETCORE_/DOTNET_ prefiksli variantlar ham bor, shuning uchun hammasini
# tozalab, ikkalasini dev satriga qadaymiz (docker-compose.dev.yml ga mos).
DEV_DB="Host=127.0.0.1;Port=15432;Database=cc01_access;Username=cc01;Password=cc01_dev_only"
while IFS= read -r v; do
  unset "$v"
done < <(compgen -e | grep -iE '^((ASPNETCORE|DOTNET)_)?(CONNECTIONSTRINGS__ACCESS|CC01_ACCESS_DB)$' || true)
export CC01_ACCESS_DB="$DEV_DB" ConnectionStrings__Access="$DEV_DB"

AP_PUBLIC_PORT=${AP_PUBLIC_PORT:-15978}
AP_INTERNAL_PORT=${AP_INTERNAL_PORT:-15981}
EDGE_HTTP_PORT=${EDGE_HTTP_PORT:-18080}
EDGE_TLS_PORT=${EDGE_TLS_PORT:-18443}
EDGE_EVENT_PORT=${EDGE_EVENT_PORT:-14321}
ORIGIN_PORT=${ORIGIN_PORT:-18099}

# Yangilash oralig'i (R). Sof son yoki `Ns` ko'rinishida.
RENEW=${CC01_ACCESS_RENEW:-30s}
R_S=${RENEW%s}
case "$R_S" in
  ''|*[!0-9]*) echo "✘ CC01_ACCESS_RENEW sekundlarda bo'lishi kerak (masalan 30s): $RENEW"; exit 1 ;;
esac
if [ "$R_S" -lt 1 ] || [ "$R_S" -gt 50 ]; then
  echo "✘ CC01_ACCESS_RENEW 1s..50s oralig'ida bo'lishi kerak: $RENEW"; exit 1
fi
TIMEOUT_S=3                   # CC01_ACCESS_TIMEOUT standarti
BOUND_S=$((R_S + TIMEOUT_S))  # nazariy eng yomon holat
SLO_S=60
USAGE_S=10                    # CC01_USAGE_INTERVAL (sukut 60s; demo uchun qisqa)

DOMAIN=cc01.test
MTLS=${MTLS:-1}
AP_PUBLIC="http://127.0.0.1:$AP_PUBLIC_PORT"
if [ "$MTLS" = "1" ]; then
  AP_INTERNAL="https://127.0.0.1:$AP_INTERNAL_PORT"
else
  AP_INTERNAL="http://127.0.0.1:$AP_INTERNAL_PORT"
fi
AP_DIR="$ROOT/access-server/src/AccessServer.Api"
AP_DLL="$AP_DIR/bin/Debug/net10.0/AccessServer.Api.dll"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/cc01-plan-demo.XXXXXX")
CERTS="$WORK/certs"   # har ishga tushishda yangi — repodagi .dev-certs ga tegmaydi
AP_PID= EDGE_PID= ORIGIN_PID= CLI_PID=

cleanup() {
  for pid in $CLI_PID $EDGE_PID $ORIGIN_PID $AP_PID; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [ -n "${KEEP:-}" ]; then
    echo "  loglar: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

fail() {
  echo "  ✘ $*"
  echo "── edge log (oxiri) ──"; tail -15 "$WORK/edge.log" 2>/dev/null | sed 's/^/    /' || true
  echo "── klient log ──";       tail -5 "$WORK/cli.log" 2>/dev/null | sed 's/^/    /' || true
  exit 1
}

now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time*1000'; }
secs()   { awk -v ms="$1" 'BEGIN { printf "%.1f", ms/1000 }'; }

# json_field <json> <maydon> — tekis JSON'dan satr yoki son qiymat.
json_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\":\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" | head -1
}

# wait_log <fayl> <qat'iy matn> <sekund> — matn paydo bo'lguncha kutadi.
wait_log() {
  local deadline=$(( $(now_ms) + $3 * 1000 ))
  while [ "$(now_ms)" -lt "$deadline" ]; do
    grep -qF -- "$2" "$1" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

wait_http_ok() {
  local i
  for i in $(seq 1 "$2"); do
    curl -sf -o /dev/null --max-time 2 "$1" && return 0
    sleep 1
  done
  return 1
}

port_free() {
  ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

through_tunnel() {
  curl -s --max-time 5 -H "Host: $SUB.$DOMAIN" "http://127.0.0.1:$EDGE_HTTP_PORT/" || true
}

start_ap() {
  # Development: tasdiqlash tokeni log'ga yoziladi (LoggingEmailSender).
  # Renewal grantlari Debug darajasida log'lanadi — edge AP'ga qayta
  # ulanganini shu yozuvdan bilamiz.
  # Admin kaliti `env` argv'iga emas, eksport orqali beriladi.
  local tls=()
  if [ "$MTLS" = "1" ]; then
    tls=(Internal__Tls__CertPath="$CERTS/ap.pem" Internal__Tls__KeyPath="$CERTS/ap.key"
         Internal__Tls__ClientCaPath="$CERTS/ca.pem"
         Internal__Tls__AllowedClients="edge-dev,operator-dev")
  fi
  (cd "$AP_DIR" && export Internal__AdminKey="$ADMIN_KEY" && exec env ${tls[@]+"${tls[@]}"} \
    ASPNETCORE_ENVIRONMENT=Development \
    ConnectionStrings__Access="$DEV_DB" \
    Public__Address=127.0.0.1 Public__Port="$AP_PUBLIC_PORT" \
    Internal__Address=127.0.0.1 Internal__Port="$AP_INTERNAL_PORT" \
    'Logging__LogLevel__AccessServer.Api.Grpc.TunnelAuthorizationService=Debug' \
    dotnet "$AP_DLL") >"$1" 2>&1 &
  AP_PID=$!
  wait_http_ok "$AP_PUBLIC/readyz" 60 || { tail -20 "$1"; fail "AP ko'tarilmadi"; }
}

for p in $AP_PUBLIC_PORT $AP_INTERNAL_PORT $EDGE_HTTP_PORT $EDGE_TLS_PORT $EDGE_EVENT_PORT $ORIGIN_PORT; do
  port_free "$p" || { echo "✘ port band: $p (muhit o'zgaruvchisi bilan almashtiring)"; exit 1; }
done

echo "── dev Postgres va migratsiyalar ──"
make -s --no-print-directory -C "$ROOT" dev-up DOCKER_CONTEXT="$DOCKER_CONTEXT" >/dev/null 2>&1 \
  || fail "make dev-up (Docker konteksti: $DOCKER_CONTEXT)"
for i in $(seq 1 30); do
  make -s --no-print-directory -C "$ROOT" db-update >"$WORK/db.log" 2>&1 && break
  [ "$i" -eq 30 ] && { tail -5 "$WORK/db.log"; fail "migratsiya qo'llanmadi"; }
  sleep 2
done
echo "  ✔ cc01_access oxirgi sxemada"

echo "── build ──"
(cd "$ROOT" && go build -o "$WORK/cc01-edge" ./core-server \
  && go build -o "$WORK/cc01" ./cli-client \
  && go build -o "$WORK/origin" ./core-server/testdata/origin)
dotnet build "$AP_DIR" --nologo -v q >"$WORK/dotnet-build.log" 2>&1 \
  || { tail -20 "$WORK/dotnet-build.log"; fail "AP qurilmadi"; }
echo "  ✔ edge, klient, origin, AP"

EDGE_TLS=()
if [ "$MTLS" = "1" ]; then
  echo "── mTLS sertifikatlari ──"
  CC01_DEV_CERTS="$CERTS" "$ROOT/deploy/dev-certs.sh" >"$WORK/certs.log" 2>&1 \
    || { cat "$WORK/certs.log"; fail "sertifikatlar yaratilmadi"; }
  echo "  ✔ ichki CA, ap, edge (CN=edge-dev), operator (CN=operator-dev), begona CA"
  EDGE_TLS=(CC01_ACCESS_TLS_CA="$CERTS/ca.pem" CC01_ACCESS_TLS_CERT="$CERTS/edge.pem"
            CC01_ACCESS_TLS_KEY="$CERTS/edge.key")
  # macOS'da .NET server tomonda TLS 1.3 ni qo'llamaydi (SecureTransport) —
  # lokal AP faqat TLS 1.2 da gaplashadi. Edge buni faqat loopback'dagi AP
  # uchun qabul qiladi; Linux'da 1.3 sinaladi.
  if [ "$(uname -s)" = "Darwin" ]; then
    EDGE_TLS+=(CC01_ACCESS_TLS_MIN=1.2)
    echo "  macOS: edge→AP TLS 1.2 (CC01_ACCESS_TLS_MIN=1.2, faqat loopback)"
  fi
  export CC01_ADMIN_CERT="$CERTS/operator.pem" CC01_ADMIN_CERT_KEY="$CERTS/operator.key" \
         CC01_ADMIN_CA="$CERTS/ca.pem"
fi

echo "── AP ──"
ADMIN_KEY=$(openssl rand -hex 24)
start_ap "$WORK/ap.log"
if [ "$MTLS" = "1" ]; then
  echo "  public $AP_PUBLIC, ichki $AP_INTERNAL (mTLS + admin kaliti)"
else
  echo "  public $AP_PUBLIC, ichki $AP_INTERNAL (h2c, admin kaliti bilan)"
fi

echo "── edge ──"
# Bo'sh massiv `set -u` da bash 3.2 (macOS) uchun "unbound variable" —
# shuning uchun ${a[@]+"${a[@]}"} shakli.
env ${EDGE_TLS[@]+"${EDGE_TLS[@]}"} CC01_DOMAIN=$DOMAIN \
  CC01_TLS_CERT="$ROOT/core-server/server/sample.crt" \
  CC01_TLS_KEY="$ROOT/core-server/server/sample.key" \
  CC01_PUBLIC_PORT="$EDGE_HTTP_PORT" CC01_PUBLIC_TLS_PORT="$EDGE_TLS_PORT" \
  CC01_EVENT_PORT="$EDGE_EVENT_PORT" \
  CC01_ACCESS_ADDR="127.0.0.1:$AP_INTERNAL_PORT" \
  CC01_ACCESS_RENEW="${R_S}s" \
  CC01_USAGE_INTERVAL="${USAGE_S}s" \
  "$WORK/cc01-edge" >"$WORK/edge.log" 2>&1 &
EDGE_PID=$!
# Yangilash yoqilganini edge'ning o'zi aytishi kerak — aks holda o'lchov
# hech narsani isbotlamaydi.
wait_log "$WORK/edge.log" "qayta tekshiriladi" 10 \
  || { kill -0 "$EDGE_PID" 2>/dev/null || fail "edge ko'tarilmadi"; fail "edge'da yangilash yoqilmagan"; }
grep -m1 "qayta tekshiriladi" "$WORK/edge.log" | cut -c21- | sed 's/^/  /'

"$WORK/origin" -listen "127.0.0.1:$ORIGIN_PORT" >"$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!

echo
echo "═══ hisob, token, tunnel ═══"
STAMP=$(date +%s)
EMAIL="plan-demo-$STAMP@example.test"
PASSWORD="plan-demo-parol-$STAMP"
SUB="pd$STAMP"

REG=$(curl -sf -X POST "$AP_PUBLIC/v1/auth/register" -H 'content-type: application/json' \
  -d "{\"fullName\":\"Plan Demo\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"subscribe\":false}") \
  || fail "ro'yxatdan o'tish"
SLUG=$(json_field "$REG" tenantSlug)

wait_log "$WORK/ap.log" "$EMAIL" 5 || fail "tasdiqlash xati log'da yo'q"
VERIFY=$(grep -F "$EMAIL" "$WORK/ap.log" | sed -n 's/.*Token: \([^ ]*\).*/\1/p' | tail -1)
curl -sf -X POST "$AP_PUBLIC/v1/auth/verify-email" -H 'content-type: application/json' \
  -d "{\"token\":\"$VERIFY\"}" >/dev/null || fail "email tasdiqlanmadi"

LOGIN=$(curl -sf -X POST "$AP_PUBLIC/v1/auth/login" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}") || fail "login"
JWT=$(json_field "$LOGIN" accessToken)

TOK=$(curl -sf -X POST "$AP_PUBLIC/v1/tokens" -H "authorization: Bearer $JWT" \
  -H 'content-type: application/json' -d '{"name":"plan-demo"}') || fail "API token"
TOKEN_ID=$(json_field "$TOK" id)
SECRET=$(json_field "$TOK" secret)
echo "  tenant $SLUG, token #$TOKEN_ID (sir faqat muhit o'zgaruvchisida)"

# Token buyruq qatoriga emas, muhitga beriladi (ps'da ko'rinmaydi).
CC01_TOKEN="$SECRET" "$WORK/cc01" -server "127.0.0.1:$EDGE_EVENT_PORT" \
  -local "127.0.0.1:$ORIGIN_PORT" -proto http -subdomain "$SUB" -inspect "" \
  >"$WORK/cli.log" 2>&1 &
CLI_PID=$!

wait_log "$WORK/edge.log" "[tunnel-opened] $SUB.$DOMAIN" 10 || fail "tunnel ochilmadi"
OPENED=$(grep -F "[tunnel-opened] $SUB.$DOMAIN" "$WORK/edge.log" | tail -1)
TID=$(printf '%s' "$OPENED" | sed -n 's/.*\[tunnel-opened\] \([^ ]*\) .*/\1/p')
echo "  ${OPENED#* * }"
printf '%s' "$OPENED" | grep -q "tenant=$SLUG plan=free max_conns=24" \
  || fail "yangi tenant Free (24) bilan ochilmadi"

BODY=$(through_tunnel)
printf '%s' "$BODY" | grep -q "salom cc01 tunnelidan" || fail "tunnel orqali javob yo'q: $BODY"
echo "  ✔ trafik o'tyapti: $BODY"

echo
echo "═══ tarif o'zgarishi → ochiq tunnel (chegara ${BOUND_S} s, SLO ${SLO_S} s) ═══"
MAX_MS=0
change_plan() { # <plan> <kutilgan max_conns>
  local t0 t1 ms out
  t0=$(now_ms)
  out=$(CC01_ADMIN_KEY="$ADMIN_KEY" make -s --no-print-directory -C "$ROOT" ap-set-plan \
    AP_INTERNAL="$AP_INTERNAL" SLUG="$SLUG" PLAN="$1" ACTOR=plan-demo REASON="plan-demo $1") \
    || fail "ap-set-plan $1: $out"
  printf '%s' "$out" | grep -q '"changed":true' || fail "tarif o'zgarmadi: $out"
  wait_log "$WORK/edge.log" "[tunnel-limits] $TID plan=$1 max_conns=$2" "$SLO_S" \
    || fail "$SLO_S s ichida [tunnel-limits] plan=$1 max_conns=$2 kelmadi"
  t1=$(now_ms)
  ms=$((t1 - t0))
  [ "$ms" -gt "$MAX_MS" ] && MAX_MS=$ms
  echo "  ✔ $1 (max_conns=$2): o'lchandi $(secs "$ms") s"
}
change_plan pro 128
change_plan enterprise 1024
change_plan free 24
echo "  eng ko'pi: $(secs "$MAX_MS") s (≤ ${BOUND_S} s kutilgan)"
[ "$MAX_MS" -le $((SLO_S * 1000)) ] || fail "60 s SLO buzildi"

PLAN_JSON=$(curl -sf "$AP_PUBLIC/v1/plan" -H "authorization: Bearer $JWT") || fail "GET /v1/plan"
printf '%s' "$PLAN_JSON" | grep -q '"plan":"free"' || fail "GET /v1/plan: $PLAN_JSON"
echo "  ✔ GET /v1/plan: plan=free maxConnsPerTunnel=$(json_field "$PLAN_JSON" maxConnsPerTunnel)"

AUDIT=$(docker --context "$DOCKER_CONTEXT" exec cc01-dev-postgres \
  psql -U cc01 -d cc01_access -tA -c \
  "SELECT count(*) FROM audit_events WHERE action = 'plan.changed' AND target = 'tenant:$SLUG'")
[ "$AUDIT" = "3" ] || fail "audit_events: 3 ta plan.changed kutilgan, $AUDIT bor"
echo "  ✔ audit_events: 3 ta plan.changed (actor=operator:plan-demo)"

echo
echo "═══ A-S19: public portda soxta Host ═══"
spoof() { # <yo'l> [qo'shimcha curl argumentlari...]
  local path=$1; shift
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" \
    -H "Host: 127.0.0.1:$AP_INTERNAL_PORT" "$AP_PUBLIC$path"
}
# Kalit stdin orqali (`-H @-`) — ap-set-plan bilan bir xil, argv'da yo'q.
CODE=$(printf 'X-Cc01-Admin-Key: %s\n' "$ADMIN_KEY" | spoof "/internal/v1/tenants/$SLUG/subscription" -X PUT \
  -H @- -H 'X-Cc01-Actor: hujumchi' \
  -H 'content-type: application/json' -d '{"plan":"enterprise"}')
[ "$CODE" = "404" ] || fail "operator API public portda javob berdi: $CODE"
echo "  ✔ PUT /internal/v1/... (to'g'ri kalit bilan ham) → 404"

CODE=$(spoof "/cc01.v1.AccessInternalService/AuthorizeTunnel" -X POST \
  -H 'content-type: application/grpc' --data-binary @/dev/null)
[ "$CODE" = "404" ] || fail "gRPC public portda javob berdi: $CODE"
echo "  ✔ gRPC AuthorizeTunnel → 404"

curl -sf "$AP_PUBLIC/v1/plan" -H "authorization: Bearer $JWT" | grep -q '"plan":"free"' \
  || fail "soxta so'rov tarifni o'zgartirdi"
echo "  ✔ tarif o'zgarmadi (free)"

if [ "$MTLS" = "1" ]; then
  echo
  echo "═══ A-S5: ichki listener mTLS ═══"
  # internal <nom> [curl argumentlari...] — HTTP kodi; TLS rad etsa "000".
  internal() {
    local name=$1; shift
    printf 'X-Cc01-Admin-Key: %s\n' "$ADMIN_KEY" | curl -s -o /dev/null -w '%{http_code}' \
      --max-time 5 --http2 --cacert "$CERTS/ca.pem" "$@" -X PUT \
      -H @- -H 'X-Cc01-Actor: hujumchi' -H 'content-type: application/json' \
      -d '{"plan":"enterprise"}' "$AP_INTERNAL/internal/v1/tenants/$SLUG/subscription" || true
  }
  CODE=$(internal "sertifikatsiz")
  [ "$CODE" = "000" ] || fail "sertifikatsiz ulanish qabul qilindi: $CODE"
  echo "  ✔ klient sertifikatisiz → TLS rad etdi"
  CODE=$(internal "begona CA" --cert "$CERTS/rogue-edge.pem" --key "$CERTS/rogue-edge.key")
  [ "$CODE" = "000" ] || fail "begona CA sertifikati qabul qilindi: $CODE"
  echo "  ✔ begona CA imzolagan CN=edge-dev → TLS rad etdi"
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --http2-prior-knowledge \
    -X POST "http://127.0.0.1:$AP_INTERNAL_PORT/cc01.v1.AccessInternalService/AuthorizeTunnel" \
    -H 'content-type: application/grpc' --data-binary @/dev/null || true)
  [ "$CODE" = "000" ] || fail "ichki port shifrlanmagan h2c ga javob berdi: $CODE"
  echo "  ✔ shifrlanmagan h2c → ulanish uzildi"
  curl -sf "$AP_PUBLIC/v1/plan" -H "authorization: Bearer $JWT" | grep -q '"plan":"free"' \
    || fail "rad etilgan ulanish tarifni o'zgartirdi"
  echo "  ✔ tarif o'zgarmadi; edge va operator esa yuqorida mTLS orqali ishladi"
fi

echo
echo "═══ usage: edge sanaydi → AP saqlaydi → GET /v1/usage ═══"
# usage_field <maydon> — `totals` dagi qiymat (javobda totals daily'dan oldin).
usage_json() { curl -sf "$AP_PUBLIC/v1/usage" -H "authorization: Bearer $JWT"; }
usage_field() { json_field "$(usage_json)" "$1"; }
# wait_usage <min connections> <sekund> — totals.connections shu qiymatga
# yetguncha kutadi.
wait_usage() {
  local deadline=$(( $(now_ms) + $2 * 1000 )) c
  while [ "$(now_ms)" -lt "$deadline" ]; do
    c=$(usage_field connections); c=${c:-0}
    [ "$c" -ge "$1" ] && return 0
    sleep 1
  done
  return 1
}
wait_usage 1 $((3 * USAGE_S)) || fail "GET /v1/usage da ulanish ko'rinmadi: $(usage_json)"
USAGE=$(usage_json)
U1_CONN=$(json_field "$USAGE" connections)
U1_OUT=$(json_field "$USAGE" bytesOut)
[ "${U1_OUT:-0}" -gt 0 ] || fail "bytesOut 0: $USAGE"
[ "$(json_field "$USAGE" bytesIn)" -gt 0 ] || fail "bytesIn 0: $USAGE"
grep -qF "[usage-reported]" "$WORK/edge.log" || fail "edge [usage-reported] yozmadi"
echo "  ✔ connections=$U1_CONN bytesIn=$(json_field "$USAGE" bytesIn) bytesOut=$U1_OUT tunnelHours=$(json_field "$USAGE" tunnelHours)"

echo
echo "═══ fail-static: AP o'chirildi ═══"
kill "$AP_PID"; wait "$AP_PID" 2>/dev/null || true; AP_PID=
DOWN_AT=$(now_ms)
wait_log "$WORK/edge.log" "[tunnel-renew-failed] $TID" $((BOUND_S + 5)) \
  || fail "[tunnel-renew-failed] yozilmadi"
echo "  ✔ $(secs $(( $(now_ms) - DOWN_AT ))) s da: $(grep -F "[tunnel-renew-failed] $TID" "$WORK/edge.log" | head -1 | cut -c21- | cut -c1-110)"
# 2R kutamiz: bir necha muvaffaqiyatsiz yangilashdan keyin ham tunnel tirik.
REST=$(( 2 * R_S * 1000 - ($(now_ms) - DOWN_AT) ))
[ "$REST" -gt 0 ] && sleep "$(secs "$REST")"
BODY=$(through_tunnel)
printf '%s' "$BODY" | grep -q "salom cc01 tunnelidan" || fail "AP'siz tunnel ishlamay qoldi: $BODY"
FAILS=$(grep -cF "[tunnel-renew-failed] $TID" "$WORK/edge.log")
grep -qF "[tunnel-revoked] $TID" "$WORK/edge.log" && fail "AP yo'qligida tunnel yopildi"
kill -0 "$CLI_PID" 2>/dev/null || fail "klient chiqib ketdi"
echo "  ✔ $((2 * R_S)) s dan keyin ham trafik o'tyapti, $FAILS ta qayta urinish, tunnel ochiq"

echo
echo "═══ token bekor qilinadi → ochiq tunnel yopiladi ═══"
start_ap "$WORK/ap2.log"
UP_AT=$(now_ms)
# Edge gRPC kanali backoff bilan qayta ulanadi; birinchi muvaffaqiyatli
# yangilashni AP'ning Debug yozuvidan kutamiz.
wait_log "$WORK/ap2.log" "Lease yangilandi: $SUB" 180 || fail "edge AP'ga qayta ulanmadi"
echo "  ✔ AP qaytdi, edge $(secs $(( $(now_ms) - UP_AT ))) s da yangilashni tikladi"
# AP o'chiq paytda o'tgan trafik navbatda kutgan bo'lishi kerak.
grep -qF "[usage-report-failed]" "$WORK/edge.log" || fail "AP o'chiqligida [usage-report-failed] yo'q"
wait_usage $((U1_CONN + 1)) $((3 * USAGE_S)) \
  || fail "AP o'chiq paytdagi trafik usage'ga yetmadi: $(usage_json)"
echo "  ✔ AP o'chiq paytdagi ulanish navbatdan yetib keldi: connections $U1_CONN → $(usage_field connections)"

REV_AT=$(now_ms)
curl -sf -X DELETE "$AP_PUBLIC/v1/tokens/$TOKEN_ID" -H "authorization: Bearer $JWT" \
  || fail "token bekor qilinmadi"
DEADLINE=$(( REV_AT + SLO_S * 1000 ))
while kill -0 "$CLI_PID" 2>/dev/null && [ "$(now_ms)" -lt "$DEADLINE" ]; do sleep 0.2; done
kill -0 "$CLI_PID" 2>/dev/null && fail "$SLO_S s ichida klient yopilmadi"
REV_MS=$(( $(now_ms) - REV_AT ))
set +e; wait "$CLI_PID"; CLI_EXIT=$?; set -e
CLI_PID=
[ "$CLI_EXIT" = "1" ] || fail "klient chiqish kodi 1 emas: $CLI_EXIT"
grep -q "tunnel yopildi: TOKEN_REVOKED" "$WORK/cli.log" || fail "klient TOKEN_REVOKED ko'rsatmadi"
echo "  ✔ klient $(secs "$REV_MS") s da chiqdi (kod 1): $(grep -o 'tunnel yopildi: TOKEN_REVOKED.*' "$WORK/cli.log")"
wait_log "$WORK/edge.log" "[tunnel-closed] $TID" 5 || fail "edge tunnelni yopmadi"
grep -qF "[tunnel-revoked] $TID code=TOKEN_REVOKED" "$WORK/edge.log" || fail "[tunnel-revoked] yo'q"
echo "  ✔ edge: [tunnel-revoked] $TID code=TOKEN_REVOKED, [tunnel-closed]"

BODY=$(through_tunnel)
printf '%s' "$BODY" | grep -q "tunnel not found" || fail "registrda tunnel qoldi: $BODY"
echo "  ✔ registr bo'sh: $SUB.$DOMAIN → tunnel not found"

set +e
CC01_TOKEN="$SECRET" "$WORK/cc01" -server "127.0.0.1:$EDGE_EVENT_PORT" \
  -local "127.0.0.1:$ORIGIN_PORT" -subdomain "$SUB" -inspect "" >"$WORK/cli2.log" 2>&1
REOPEN=$?
set -e
[ "$REOPEN" != "0" ] && grep -q "TOKEN_REVOKED" "$WORK/cli2.log" || fail "bekor token bilan qayta ochildi"
echo "  ✔ bekor token bilan yangi tunnel ochilmaydi (TOKEN_REVOKED)"

echo
echo "── natija ──"
echo "  tarif o'zgarishi ochiq tunnelga eng ko'pi $(secs "$MAX_MS") s da yetdi (SLO ${SLO_S} s, chegara ${BOUND_S} s),"
echo "  token bekor qilinishi $(secs "$REV_MS") s da tunnelni yopdi, AP'siz tunnel ishlashda davom etdi,"
echo "  operator API va gRPC public portda soxta Host bilan 404,"
echo "  usage AP o'chiq paytda yo'qolmadi (navbat → qayta yuborish)"
