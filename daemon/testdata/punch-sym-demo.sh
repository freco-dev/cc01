#!/bin/sh
# Birthday punching: node-1 SYMMETRIC NAT ortida, node-2 CONE NAT
# ortida.
#
#   net-public   172.36.0.0/24   cp+relay, gw-a:eth0, gw-b:eth0
#   net-a        172.36.1.0/24   gw-a:eth1, node-1
#   net-b        172.36.2.0/24   gw-b:eth1, node-2
#
# node-1 ning tashqi porti har oqimda o'zgaradi, ya'ni STUN aytgan
# manzil node-2 uchun yaroqsiz — oddiy teshik ochish ishlamaydi.
#
# Birthday punching ikkala yarimni birlashtiradi:
#
#   node-1 (symmetric)  N ta vaqtinchalik soketdan node-2 ga yozadi
#                       va o'z NAT'ida N ta tashqi port ochadi
#   node-2 (cone)       node-1 ning IP'sida K ta tasodifiy portga
#                       ASOSIY soketidan yozadi
#
# Taxminlardan biri sepilgan portlardan biriga tushsa, teshik
# ochiladi. N=K=256 da bir bosqichning ehtimoli ~63%, shuning uchun
# demo bir necha bosqichni kutadi.
#
# ⚠️ Ikkala tomon ham symmetric bo'lsa bu ISHLAMAYDI — taxmin
# qiluvchining o'z tashqi porti ham har oqimda o'zgaradi. O'sha holat
# `make relay-demo` da va u to'g'ri ravishda relayda qoladi.
#
# Kutilgan natija: ulanish relaydan boshlanadi, keyin ikkala tomon
# bir-birining public manziliga disco ping yuboradi, NAT'larda
# conntrack yozuvlari paydo bo'ladi va yo'l `direct-active` ga o'tadi.
set -e

DOCKER="docker --context desktop-linux"
IMAGE=cc01-cp-demo
PUB=cc01-sn-pub
NETA=cc01-sn-a
NETB=cc01-sn-b
TOKEN=demo-shared-secret-0123456789

cleanup() {
  $DOCKER rm -f cc01-scp cc01-sgwa cc01-sgwb cc01-s1 cc01-s2 >/dev/null 2>&1 || true
  $DOCKER network rm $PUB $NETA $NETB >/dev/null 2>&1 || true
}
if [ -z "${KEEP:-}" ]; then
  trap cleanup EXIT
fi
cleanup

echo "── image ──"
$DOCKER build -q -t $IMAGE -f daemon/testdata/Dockerfile.cp . >/dev/null

echo "── tarmoqlar ──"
$DOCKER network create --subnet 172.36.0.0/24 $PUB  >/dev/null
$DOCKER network create --subnet 172.36.1.0/24 $NETA >/dev/null
$DOCKER network create --subnet 172.36.2.0/24 $NETB >/dev/null

# Cone NAT: overlay portidan chiqqan UDP uchun tashqi port MAJBURAN
# saqlanadi. Shunda mapping manzilga bog'liq bo'lmaydi va STUN bergan
# javob har qanday peer uchun to'g'ri bo'ladi.
gateway() {
  name=$1; pubip=$2; privnet=$3; privip=$4; subnet=$5
  $DOCKER run -d --name "$name" --network $PUB --ip "$pubip" \
    --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
    --entrypoint sh $IMAGE -c 'sleep infinity' >/dev/null
  $DOCKER network connect --ip "$privip" "$privnet" "$name"
  # $6 — "symmetric" bo'lsa har oqimga tasodifiy tashqi port.
  if [ "${6:-}" = "symmetric" ]; then
    $DOCKER exec "$name" iptables -t nat -A POSTROUTING \
      -s "$subnet" ! -d "$subnet" -j MASQUERADE --random
  else
    $DOCKER exec "$name" iptables -t nat -A POSTROUTING \
      -s "$subnet" ! -d "$subnet" -j MASQUERADE
  fi

  # Kiruvchi: faqat ichkaridan boshlangan oqimlar.
  #
  # Kutilmagan paket TASHLANADI va — bu yerda muhimi — conntrack
  # yozuvi TASDIQLANMAYDI, chunki DROP tasdiqlash hook'idan oldin
  # keladi. Busiz o'sha yozuv keyin ichkaridan chiqadigan oqimga
  # kerakli tashqi portni band qilib qo'yardi va teshik hech qachon
  # ochilmasdi. Haqiqiy restricted-cone NAT ham kutilmagan paketni
  # mapping jadvaliga umuman kiritmaydi.
  #
  # Paket shlyuzning O'ZIGA adreslangan (port forwarding yo'q),
  # shuning uchun u FORWARD emas, INPUT ga tushadi.
  $DOCKER exec "$name" iptables -A INPUT \
    -p udp --dport 51820 -m conntrack --ctstate NEW -j DROP
  $DOCKER exec "$name" iptables -A FORWARD \
    -d "$subnet" -m conntrack --ctstate NEW,INVALID -j DROP
}

echo "── NAT shlyuzlari ──"
gateway cc01-sgwa 172.36.0.2 $NETA 172.36.1.2 172.36.1.0/24 symmetric
gateway cc01-sgwb 172.36.0.3 $NETB 172.36.2.2 172.36.2.0/24 cone
echo "  gw-a → 172.36.0.2  (symmetric: har oqimga tasodifiy port)"
echo "  gw-b → 172.36.0.3  (cone: port saqlanadi)"

echo "── Control Plane + STUN + relay ──"
$DOCKER run -d --name cc01-scp --network $PUB --ip 172.36.0.5 \
  --entrypoint cc01-cp $IMAGE \
  -listen :8443 -stun :3478 -relay 51821 -relay-endpoint 172.36.0.5:51821 \
  -tenant-net 'fd00:cc01:5717::/64' -auth-token "$TOKEN" >/dev/null
sleep 2

# CP vaqtinchalik sertifikat yaratdi va pinini chiqardi. Nodelar
# AYNAN shu pin bilan ulanadi — ommaviy CA self-signed sertifikatni
# tasdiqlamaydi, pin esa undan kuchliroq: u aniq bitta kalitga
# bog'lanadi.
PIN=$($DOCKER logs cc01-scp 2>&1 | grep -o 'sha256/[A-Za-z0-9+/=]*' | head -1)
if [ -z "$PIN" ]; then
  echo "✘ CP pini olinmadi"; exit 1
fi
echo "  CP pin: $PIN"

KEY() { $DOCKER run --rm --entrypoint cc01d $IMAGE -genkey 2>/dev/null; }

echo "── nodelar ──"
node() {
  name=$1; net=$2; ip=$3; gw=$4; host=$5
  $DOCKER run -d --name "$name" --network "$net" --ip "$ip" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    --entrypoint sh $IMAGE -c 'sleep infinity' >/dev/null
  $DOCKER exec "$name" sh -c "ip route del default 2>/dev/null; ip route add default via $gw"
  $DOCKER exec -d "$name" sh -c "cc01d -key '$(KEY)' -cp 172.36.0.5:8443 \
    -cp-token '$TOKEN' -cp-pin '$PIN' -stun 172.36.0.5:3478 -hostname $host -listen 51820 -v \
    >/tmp/$host.log 2>&1"
}
node cc01-s1 $NETA 172.36.1.11 172.36.1.2 node-1
node cc01-s2 $NETB 172.36.2.12 172.36.2.2 node-2
sleep 4

ADDR() { $DOCKER exec "cc01-$1" grep -o 'addr=fd00:[^ ]*' "/tmp/$2.log" 2>/dev/null | head -1 | cut -d= -f2 | cut -d/ -f1; }
A1=$(ADDR s1 node-1); A2=$(ADDR s2 node-2)

echo
echo "═══ nodelar nimani aniqladi ═══"
$DOCKER exec cc01-s1 grep -E 'public manzil|relayga ulandi' /tmp/node-1.log || true
$DOCKER exec cc01-s2 grep -E 'public manzil|relayga ulandi' /tmp/node-2.log || true

echo
echo "═══ trafik boshlanadi (yo'l relaydan ochiladi) ═══"
$DOCKER exec cc01-s1 ping -6 -c 3 -W 3 "$A2"

echo
echo "═══ teshik ochilishini kutamiz ═══"
echo "  (oddiy probe'lar 15 s urinadi, keyin birthday punching boshlanadi)"

deadline=$(( $(date +%s) + 90 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if $DOCKER exec cc01-s1 cc01 peer list 2>/dev/null | grep -q direct-active; then
    echo "  ✔ to'g'ridan-to'g'ri yo'l ochildi"
    break
  fi
  sleep 5
done

echo
echo "── node-1 (symmetric NAT) ──"
$DOCKER exec cc01-s1 cc01 peer list
echo "── node-2 (cone NAT) ──"
$DOCKER exec cc01-s2 cc01 peer list

echo
echo "═══ teshik ochish jarayoni ═══"
$DOCKER exec cc01-s1 sh -c "grep -E 'teshik|yo.l holati' /tmp/node-1.log" || echo "  (yozuv yo'q)"

echo
echo "═══ dalil: node-2 node-1 ga qaysi port orqali yetdi ═══"
echo "  node-1 STUN orqali e'lon qilgan manzil:"
$DOCKER exec cc01-s1 grep -o 'endpoint=172.36.0.2:[0-9]*' /tmp/node-1.log | head -1 | sed 's/^/    /'
echo "  node-2 haqiqatda ishlatayotgan manzil:"
$DOCKER exec cc01-s2 cc01 peer list | awk 'NR>1 {print "    " $NF}'
echo
echo "  Ular boshqa-boshqa: ikkinchisi e'lon qilinmagan, TAXMIN bilan topilgan."

echo
echo "═══ trafik ═══"
$DOCKER exec cc01-s1 ping -6 -c 3 -W 3 "$A2"
