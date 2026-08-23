#!/bin/sh
# Control Plane klasteri: uchta replika, lider failover.
#
# DoD (DEV_SPEC §8): 3 replika, lider yo'qolganda yangisi 5 soniyadan
# tez tanlanadi va tasdiqlangan ijaralar YO'QOLMAYDI.
#
# Demo nimani ko'rsatadi:
#   1. Uchta cc01-cp ko'tariladi va bitta lider tanlaydi
#   2. Node lidergа ulanib manzil oladi — ijara jurnalga yoziladi
#   3. Lider o'ldiriladi
#   4. Yangi lider tanlanadi va o'sha ijara unda TURIBDI
#   5. Kvorum yo'qolganda (yana bittasi o'lsa) yozuv rad etiladi
set -e

DOCKER="docker --context desktop-linux"
IMAGE=cc01-cp-demo
NET=cc01-raft-net
TOKEN=demo-shared-secret-0123456789

cleanup() {
  $DOCKER rm -f cc01-cp1 cc01-cp2 cc01-cp3 cc01-rn1 cc01-rn2 >/dev/null 2>&1 || true
  $DOCKER network rm $NET >/dev/null 2>&1 || true
}
if [ -z "${KEEP:-}" ]; then
  trap cleanup EXIT
fi
cleanup

echo "── image ──"
$DOCKER build -q -t $IMAGE -f daemon/testdata/Dockerfile.cp . >/dev/null

echo "── tarmoq ──"
$DOCKER network create --subnet 172.37.0.0/24 $NET >/dev/null

PEERS="cp1=172.37.0.11:7000,cp2=172.37.0.12:7000,cp3=172.37.0.13:7000"

echo "── uchta Control Plane replikasi ──"
replica() {
  n=$1; ip=$2; boot=$3
  $DOCKER run -d --name "cc01-cp$n" --network $NET --ip "$ip" \
    --entrypoint cc01-cp $IMAGE \
    -listen :8443 -tenant-net 'fd00:cc01:4a17::/64' -auth-token "$TOKEN" \
    -tls-hosts "$ip" \
    -raft-id "cp$n" -raft-bind "0.0.0.0:7000" -raft-advertise "$ip:7000" \
    -raft-dir /var/lib/cc01 -raft-peers "$PEERS" $boot >/dev/null
}

# Faqat BITTASI bootstrap qiladi: ikkitasi qilsa ikkita alohida
# klaster paydo bo'ladi va ular hech qachon birlashmaydi.
replica 1 172.37.0.11 -raft-bootstrap
replica 2 172.37.0.12 ""
replica 3 172.37.0.13 ""
sleep 5

# leader_of hozirgi liderni topadi.
#
# Log oxiridan qaraymiz: node lider bo'lib, keyin liderlikni
# yo'qotgan bo'lishi mumkin, ya'ni "lider bo'ldi" yozuvining borligi
# yetarli emas.
leader_of() {
  for n in 1 2 3; do
    last=$($DOCKER logs "cc01-cp$n" 2>&1 \
      | grep -oE "BU NODE LIDER BO'LDI|liderlik yo'qotildi" | tail -1)
    if [ "$last" = "BU NODE LIDER BO'LDI" ]; then
      echo "$n"; return
    fi
  done
  echo ""
}

echo
echo "═══ lider kim ═══"
LEADER=$(leader_of)
if [ -z "$LEADER" ]; then
  echo "  ✘ lider tanlanmadi"; $DOCKER logs cc01-cp1 2>&1 | tail -5; exit 1
fi
echo "  cp$LEADER (172.37.0.1$LEADER)"

LEADER_IP="172.37.0.1$LEADER"
PIN=$($DOCKER logs "cc01-cp$LEADER" 2>&1 | grep -o 'sha256/[A-Za-z0-9+/=]*' | head -1)

echo
echo "═══ node liderga ulanib manzil oladi ═══"
# Kalitni saqlab qo'yamiz: failover'dan keyin AYNAN shu kalit bilan
# yangi liderga ulanamiz.
NODE_KEY=$($DOCKER run --rm --entrypoint cc01d $IMAGE -genkey 2>/dev/null)

$DOCKER run -d --name cc01-rn1 --network $NET --ip 172.37.0.21 \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --entrypoint cc01d $IMAGE \
  -key "$NODE_KEY" \
  -cp "$LEADER_IP:8443" -cp-token "$TOKEN" -cp-pin "$PIN" \
  -hostname node-1 -listen 51820 >/dev/null
sleep 5

ADDR=$($DOCKER exec cc01-rn1 cc01 status 2>/dev/null | awk '/manzil/ {print $2}')
if [ -z "$ADDR" ]; then
  echo "  ✘ manzil olinmadi"; $DOCKER logs cc01-rn1 2>&1 | tail -5; exit 1
fi
echo "  berilgan manzil: $ADDR"

echo
echo "═══ liderni o'ldiramiz ═══"
START=$(date +%s%N)
$DOCKER rm -f "cc01-cp$LEADER" >/dev/null

NEW=""
while [ -z "$NEW" ]; do
  for n in 1 2 3; do
    [ "$n" = "$LEADER" ] && continue
    last=$($DOCKER logs "cc01-cp$n" 2>&1 \
      | grep -oE "BU NODE LIDER BO'LDI|liderlik yo'qotildi" | tail -1)
    if [ "$last" = "BU NODE LIDER BO'LDI" ]; then
      NEW=$n; break
    fi
  done
  [ -z "$NEW" ] || break
  if [ $(( ($(date +%s%N) - START) / 1000000 )) -gt 15000 ]; then
    echo "  ✘ 15 s ichida yangi lider tanlanmadi"; exit 1
  fi
  sleep 0.2
done
ELAPSED=$(( ($(date +%s%N) - START) / 1000000 ))

echo "  yangi lider: cp$NEW  ($ELAPSED ms ichida)"
if [ "$ELAPSED" -lt 5000 ]; then
  echo "  ✔ DoD: 5 soniyadan tez"
else
  echo "  ✘ DoD buzildi: $ELAPSED ms"
fi

echo
echo "═══ ijara saqlanib qoldimi ═══"
#
# node-1 ning o'z keshiga qarash dalil emas — u manzilni mahalliy
# saqlaydi. Boshqa kalit bilan ulanish ham dalil emas: tasodifiy
# taqsimlashda ikkita node baribir turli manzil olardi.
#
# Haqiqiy tekshiruv: AYNAN O'SHA KALIT bilan yangi liderga ulanamiz.
# Taqsimlash egasi bo'yicha idempotent, ya'ni lider ijarani bilsa
# O'SHA manzilni qaytaradi. Jurnal yo'qolgan bo'lsa — yangisini
# beradi.
NEW_IP="172.37.0.1$NEW"
NEW_PIN=$($DOCKER logs "cc01-cp$NEW" 2>&1 | grep -o 'sha256/[A-Za-z0-9+/=]*' | head -1)

$DOCKER run -d --name cc01-rn2 --network $NET --ip 172.37.0.22 \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --entrypoint cc01d $IMAGE \
  -key "$NODE_KEY" \
  -cp "$NEW_IP:8443" -cp-token "$TOKEN" -cp-pin "$NEW_PIN" \
  -hostname node-1 -listen 51820 >/dev/null
sleep 5

ADDR2=$($DOCKER exec cc01-rn2 cc01 status 2>/dev/null | awk '/manzil/ {print $2}')
echo "  eski lider bergan:  $ADDR"
echo "  yangi lider bergan: ${ADDR2:-<olinmadi>}"

if [ -z "$ADDR2" ]; then
  echo "  ✘ yangi lider manzil bermadi"
elif [ "$ADDR" = "$ADDR2" ]; then
  echo "  ✔ AYNAN o'sha manzil — ijara jurnal orqali saqlanib qolgan"
else
  echo "  ✘ boshqa manzil berildi — jurnal yo'qolgan"
fi

echo
echo "═══ kvorum yo'qolsa yozuv rad etiladimi ═══"
for n in 1 2 3; do
  if [ "$n" != "$LEADER" ] && [ "$n" != "$NEW" ]; then
    $DOCKER rm -f "cc01-cp$n" >/dev/null
    echo "  cp$n ham o'chirildi — 3 tadan 1 tasi qoldi, kvorum yo'q"
  fi
done
sleep 3

last=$($DOCKER logs "cc01-cp$NEW" 2>&1 \
  | grep -oE "BU NODE LIDER BO'LDI|liderlik yo'qotildi" | tail -1)
if [ "$last" = "liderlik yo'qotildi" ]; then
  echo "  ✔ qolgan node liderlikdan voz kechdi — yozuv qabul qilinmaydi"
else
  echo "  ✘ node hali ham o'zini lider deb hisoblayapti"
fi
