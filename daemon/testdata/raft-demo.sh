#!/bin/sh
# Control Plane klasteri: uchta replika, lider failover.
#
# DoD (DEV_SPEC §8): 3 replika, lider yo'qolganda yangisi 5 soniyadan
# tez tanlanadi va tasdiqlangan ijaralar YO'QOLMAYDI.
#
# Demo nimani ko'rsatadi:
#   1. Uchta cc01-cp ko'tariladi va bitta lider tanlaydi
#   2. Node liderga ulanib manzil oladi — ijara jurnalga yoziladi
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
  $DOCKER volume rm cc01-raft-node >/dev/null 2>&1 || true
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


echo
echo "═══ node liderni O'ZI topib manzil oladi ═══"
# Nodega uchala CP manzili beriladi va ro'yxat ataylab FOLLOWER'dan
# boshlanadi. Manzil berish Raft yozuvi — uni faqat lider bajara
# oladi, follower esa NOT_LEADER qaytaradi va klient keyingisiga
# o'tadi.
CP_LIST=""
PIN_LIST=""
for n in $(for i in 1 2 3; do [ "$i" != "$LEADER" ] && echo "$i"; done) $LEADER; do
  ip="172.37.0.1$n"
  pin=$($DOCKER logs "cc01-cp$n" 2>&1 | grep -o 'sha256/[A-Za-z0-9+/=]*' | head -1)
  CP_LIST="${CP_LIST:+$CP_LIST,}$ip:8443"
  PIN_LIST="${PIN_LIST:+$PIN_LIST,}$pin"
done
echo "  berilgan ro'yxat: $CP_LIST"
echo "  (lider cp$LEADER oxirida)"
# Kalitni saqlab qo'yamiz: failover'dan keyin AYNAN shu kalit bilan
# yangi liderga ulanamiz.
NODE_KEY=$($DOCKER run --rm --entrypoint cc01d $IMAGE -genkey 2>/dev/null)

# Node holati (sertifikat) VOLUME da: failover'dan keyin AYNAN o'sha
# node qayta ulanadi. Yangi konteyner yangi sertifikat yasasa, CP uni
# haqli ravishda rad etardi — node_id boshqa sertifikatga bog'langan.
$DOCKER volume create cc01-raft-node >/dev/null

$DOCKER run -d --name cc01-rn1 --network $NET --ip 172.37.0.21 \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v cc01-raft-node:/var/lib/cc01 \
  --entrypoint cc01d $IMAGE \
  -key "$NODE_KEY" -state-dir /var/lib/cc01 \
  -cp "$CP_LIST" -cp-token "$TOKEN" -cp-pin "$PIN_LIST" \
  -hostname node-1 -listen 51820 >/dev/null
sleep 5

ADDR=$($DOCKER exec cc01-rn1 cc01 status 2>/dev/null | awk '/manzil/ {print $2}')
if [ -z "$ADDR" ]; then
  echo "  ✘ manzil olinmadi"; $DOCKER logs cc01-rn1 2>&1 | tail -5; exit 1
fi
echo "  berilgan manzil: $ADDR"

# Node haqiqatan follower'dan o'tib ketganini tekshiramiz. Bu
# muhim: agar birinchi manzil tasodifan lider bo'lib qolsa, demo
# hech nimani isbotlamagan bo'lardi.
# ⚠️ "lider emas" ni qidirish YETARLI EMAS: u serverning xato
# matnida ham bor, ya'ni ro'yxatdan o'ta OLMAGAN node ham shu
# tekshiruvdan o'tib ketardi. Klientning o'z xabarini qidiramiz.
SKIPPED=$($DOCKER logs cc01-rn1 2>&1 | grep -c "keyingisiga o'tamiz" || true)
if [ "$SKIPPED" -eq 0 ]; then
  echo "  ✘ follower o'tkazib yuborilmadi — redirect sinalmadi"
  $DOCKER logs cc01-rn1 2>&1 | tail -5
  exit 1
fi
echo "  ✔ $SKIPPED ta follower o'tkazib yuborildi, lider topildi"

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
# Haqiqiy tekshiruv: AYNAN O'SHA NODE (o'sha kalit VA o'sha
# sertifikat) yangi liderga qayta ulanadi. Taqsimlash egasi bo'yicha
# idempotent, ya'ni lider ijarani bilsa O'SHA manzilni qaytaradi.
# Jurnal yo'qolgan bo'lsa — yangisini beradi.
#
# ⚠️ Node holati volume'da saqlanadi. Yangi sertifikat bilan
# ulanish CP tomonidan RAD ETILADI va bu to'g'ri: node_id bir marta
# sertifikatga bog'lanadi.
$DOCKER rm -f cc01-rn1 >/dev/null
# Tirik qolgan CP larning HAMMASI beriladi — qaysi biri yangi
# lider ekanini nodega AYTMAYMIZ. Haqiqiy joylashtirishda ham
# operator buni bilmaydi: lider istalgan payt almashadi.
SURVIVOR_LIST=""
SURVIVOR_PINS=""
for n in 1 2 3; do
  [ "$n" = "$LEADER" ] && continue   # o'ldirilgan
  ip="172.37.0.1$n"
  pin=$($DOCKER logs "cc01-cp$n" 2>&1 | grep -o 'sha256/[A-Za-z0-9+/=]*' | head -1)
  SURVIVOR_LIST="${SURVIVOR_LIST:+$SURVIVOR_LIST,}$ip:8443"
  SURVIVOR_PINS="${SURVIVOR_PINS:+$SURVIVOR_PINS,}$pin"
done
echo "  nodega berilgan ro'yxat: $SURVIVOR_LIST (lider aytilmagan)"

$DOCKER run -d --name cc01-rn2 --network $NET --ip 172.37.0.21 \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v cc01-raft-node:/var/lib/cc01 \
  --entrypoint cc01d $IMAGE \
  -key "$NODE_KEY" -state-dir /var/lib/cc01 \
  -cp "$SURVIVOR_LIST" -cp-token "$TOKEN" -cp-pin "$SURVIVOR_PINS" \
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
