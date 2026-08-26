#!/bin/sh
# NAT ortidagi node uchun STUN sinovi.
#
#   net-public (172.33.0.0/24)   cc01-cp, node-2, gw:eth0
#   net-private (172.33.1.0/24)  gw:eth1, node-1
#
# node-1 ning yagona chiqish yo'li — MASQUERADE qiluvchi shlyuz.
# Uning lokal manzili (172.33.1.x) tashqaridan erishib bo'lmaydi,
# ya'ni public manzilni faqat STUN ayta oladi.
set -e

DOCKER="docker --context desktop-linux"
IMAGE=cc01-cp-demo
PUB=cc01-nat-pub
PRIV=cc01-nat-priv
TOKEN=demo-shared-secret-0123456789

cleanup() {
  $DOCKER rm -f cc01-cp cc01-gw cc01-n1 cc01-n2 >/dev/null 2>&1 || true
  $DOCKER network rm $PUB $PRIV >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "── image ──"
$DOCKER build -q -t $IMAGE -f daemon/testdata/Dockerfile.cp . >/dev/null

echo "── tarmoqlar ──"
$DOCKER network create --subnet 172.33.0.0/24 $PUB >/dev/null
# `--internal` ISHLATILMAYDI: u Docker'ning o'z DROP qoidalarini
# qo'shadi va bizning shlyuzimiz orqali forwarding'ni ham to'sadi.
# O'rniga node-1 ning standart marshrutini shlyuzga yo'naltiramiz —
# uning public tarmoqqa boshqa yo'li qolmaydi.
$DOCKER network create --subnet 172.33.1.0/24 $PRIV >/dev/null

echo "── NAT shlyuzi ──"
# ip_forward ni konteyner ichidan yozib bo'lmaydi — uni ishga
# tushirishda beramiz.
$DOCKER run -d --name cc01-gw --network $PUB --ip 172.33.0.2 \
  --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
  --entrypoint sh $IMAGE -c 'sleep infinity' >/dev/null
$DOCKER network connect --ip 172.33.1.2 $PRIV cc01-gw
$DOCKER exec cc01-gw iptables -t nat -A POSTROUTING \
  -s 172.33.1.0/24 ! -d 172.33.1.0/24 -j MASQUERADE
echo "  MASQUERADE yoqildi"

echo "── Control Plane (STUN bilan) ──"
$DOCKER run -d --name cc01-cp --network $PUB --ip 172.33.0.5 \
  --entrypoint cc01-cp $IMAGE \
  -listen :8443 -stun :3478 -tenant-net 'fd00:cc01:da7::/64' -auth-token "$TOKEN" -tls-hosts 172.33.0.5 >/dev/null
sleep 2

# CP vaqtinchalik sertifikat yaratdi va pinini chiqardi. Nodelar
# AYNAN shu pin bilan ulanadi — ommaviy CA self-signed sertifikatni
# tasdiqlamaydi, pin esa undan kuchliroq: u aniq bitta kalitga
# bog'lanadi.
PIN=$($DOCKER logs cc01-cp 2>&1 | grep -o 'sha256/[A-Za-z0-9+/=]*' | head -1)
if [ -z "$PIN" ]; then
  echo "✘ CP pini olinmadi"; exit 1
fi
echo "  CP pin: $PIN"

KEY() { $DOCKER run --rm --entrypoint cc01d $IMAGE -genkey 2>/dev/null; }

echo "── node-2 (public tarmoqda) ──"
$DOCKER run -d --name cc01-n2 --network $PUB --ip 172.33.0.12 \
  --cap-add NET_ADMIN --device /dev/net/tun --entrypoint cc01d $IMAGE \
  -key "$(KEY)" -cp 172.33.0.5:8443 -cp-token "$TOKEN" -cp-pin "$PIN" \
  -stun 172.33.0.5:3478 -hostname node-2 -listen 51820 -v >/dev/null

echo "── node-1 (NAT ortida) ──"
$DOCKER run -d --name cc01-n1 --network $PRIV --ip 172.33.1.11 \
  --cap-add NET_ADMIN --device /dev/net/tun --entrypoint sh $IMAGE \
  -c 'sleep infinity' >/dev/null
$DOCKER exec cc01-n1 sh -c 'ip route del default 2>/dev/null; ip route add default via 172.33.1.2'
echo "  standart marshrut → shlyuz"

echo "── ulanish tekshiruvi ──"
if $DOCKER exec cc01-n1 ping -c 2 -W 2 172.33.0.5 >/dev/null 2>&1; then
  echo "  ✔ node-1 → CP (NAT orqali)"
else
  echo "  ✘ node-1 CP ga yeta olmadi"
  $DOCKER exec cc01-n1 ip route
  $DOCKER exec cc01-gw iptables -t nat -L POSTROUTING -n
  exit 1
fi

$DOCKER exec -d cc01-n1 sh -c "cc01d -key '$(KEY)' -cp 172.33.0.5:8443 -cp-token '$TOKEN' -cp-pin '$PIN' \
  -stun 172.33.0.5:3478 -hostname node-1 -listen 51820 -v > /tmp/n1.log 2>&1"

sleep 8

echo
echo "═══ node-1 nima aniqladi ═══"
$DOCKER exec cc01-n1 grep -E 'public manzil|tayyor' /tmp/n1.log || true

echo
echo "═══ CP node-1 ni qanday ko'rdi ═══"
$DOCKER logs cc01-cp 2>&1 | grep 'node-1' || true

echo
echo "═══ node-2 node-1 ni qayerda deb biladi ═══"
$DOCKER logs cc01-n2 2>&1 | grep 'node-1' || true

ADDR() { $DOCKER exec cc01-n1 grep -o 'addr=fd00:[^ ]*' /tmp/n1.log 2>/dev/null | head -1 | cut -d= -f2 | cut -d/ -f1; }
A1=$(ADDR)
A2=$($DOCKER logs cc01-n2 2>&1 | grep -o 'addr=fd00:[^ ]*' | head -1 | cut -d= -f2 | cut -d/ -f1)
echo
echo "  node-1 overlay: $A1"
echo "  node-2 overlay: $A2"

echo
echo "═══ NAT ortidan tashqariga (node-1 → node-2) ═══"
$DOCKER exec cc01-n1 ping -6 -c 3 -W 3 "$A2" || true

echo
echo "═══ Tashqaridan NAT ortiga (node-2 → node-1) ═══"
$DOCKER exec cc01-n2 ping -6 -c 3 -W 3 "$A1" || true

echo
echo "═══ node-1 sessiya logi ═══"
$DOCKER exec cc01-n1 grep -vE 'heartbeat|NetworkMap qo' /tmp/n1.log | tail -14 || true

echo
echo "═══ node-2 sessiya logi ═══"
$DOCKER logs cc01-n2 2>&1 | grep -vE 'heartbeat|NetworkMap qo' | tail -14

echo
echo "═══ NAT jadvali ═══"
$DOCKER exec cc01-gw sh -c 'cat /proc/net/nf_conntrack 2>/dev/null | grep udp | head -5' || echo "  (conntrack ko'rinmadi)"
