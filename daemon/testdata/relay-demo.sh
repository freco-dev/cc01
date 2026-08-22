#!/bin/sh
# Relay orqali ulanish: ikkita node HAR BIRI O'Z NAT'i ortida.
#
#   net-public   172.34.0.0/24   cp+relay, gw-a:eth0, gw-b:eth0
#   net-a        172.34.1.0/24   gw-a:eth1, node-1
#   net-b        172.34.2.0/24   gw-b:eth1, node-2
#
# Ikkala node ham CP va relayga yeta oladi, lekin BIR-BIRIGA yo'q:
# node-1 node-2 ning NAT manziliga yuborsa, gw-b da mos conntrack
# yozuvi yo'q va paket tashlanadi. Yagona yo'l — relay.
set -e

DOCKER="docker --context desktop-linux"
IMAGE=cc01-cp-demo
PUB=cc01-rl-pub
NETA=cc01-rl-a
NETB=cc01-rl-b
TOKEN=demo-shared-secret-0123456789

cleanup() {
  $DOCKER rm -f cc01-cp cc01-gwa cc01-gwb cc01-n1 cc01-n2 >/dev/null 2>&1 || true
  $DOCKER network rm $PUB $NETA $NETB >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "── image ──"
$DOCKER build -q -t $IMAGE -f daemon/testdata/Dockerfile.cp . >/dev/null

echo "── tarmoqlar ──"
$DOCKER network create --subnet 172.34.0.0/24 $PUB  >/dev/null
$DOCKER network create --subnet 172.34.1.0/24 $NETA >/dev/null
$DOCKER network create --subnet 172.34.2.0/24 $NETB >/dev/null

gateway() {
  name=$1; pubip=$2; privnet=$3; privip=$4; subnet=$5
  $DOCKER run -d --name "$name" --network $PUB --ip "$pubip" \
    --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
    --entrypoint sh $IMAGE -c 'sleep infinity' >/dev/null
  $DOCKER network connect --ip "$privip" "$privnet" "$name"
  $DOCKER exec "$name" iptables -t nat -A POSTROUTING \
    -s "$subnet" ! -d "$subnet" -j MASQUERADE
}

echo "── NAT shlyuzlari ──"
gateway cc01-gwa 172.34.0.2 $NETA 172.34.1.2 172.34.1.0/24
gateway cc01-gwb 172.34.0.3 $NETB 172.34.2.2 172.34.2.0/24
echo "  gw-a → 172.34.0.2, gw-b → 172.34.0.3"

echo "── Control Plane + STUN + relay ──"
$DOCKER run -d --name cc01-cp --network $PUB --ip 172.34.0.5 \
  --entrypoint cc01-cp $IMAGE \
  -listen :8443 -stun :3478 -relay 51821 -relay-endpoint 172.34.0.5:51821 \
  -tenant-net 'fd00:cc01:fade::/64' -auth-token "$TOKEN" >/dev/null
sleep 2

KEY() { $DOCKER run --rm --entrypoint cc01d $IMAGE -genkey 2>/dev/null; }

node() {
  name=$1; net=$2; ip=$3; gw=$4; host=$5
  $DOCKER run -d --name "$name" --network "$net" --ip "$ip" \
    --cap-add NET_ADMIN --device /dev/net/tun --entrypoint sh $IMAGE \
    -c 'sleep infinity' >/dev/null
  $DOCKER exec "$name" sh -c "ip route del default 2>/dev/null; ip route add default via $gw"
  $DOCKER exec -d "$name" sh -c "cc01d -key '$(KEY)' -cp 172.34.0.5:8443 \
    -cp-token '$TOKEN' -stun 172.34.0.5:3478 -hostname $host -listen 51820 -v \
    > /tmp/$host.log 2>&1"
}

echo "── nodelar (har biri o'z NAT'i ortida) ──"
node cc01-n1 $NETA 172.34.1.11 172.34.1.2 node-1
node cc01-n2 $NETB 172.34.2.12 172.34.2.2 node-2

sleep 10

ADDR() { $DOCKER exec "cc01-$1" grep -o 'addr=fd00:[^ ]*' "/tmp/$2.log" 2>/dev/null | head -1 | cut -d= -f2 | cut -d/ -f1; }
A1=$(ADDR n1 node-1); A2=$(ADDR n2 node-2)

echo
echo "═══ nodelar nimani aniqladi ═══"
$DOCKER exec cc01-n1 grep -E 'public manzil|relayga ulandi' /tmp/node-1.log || true
$DOCKER exec cc01-n2 grep -E 'public manzil|relayga ulandi' /tmp/node-2.log || true

echo
echo "  node-1 overlay: $A1"
echo "  node-2 overlay: $A2"

echo
echo "═══ to'g'ridan-to'g'ri yo'l bormi? ═══"
if $DOCKER exec cc01-n1 ping -c 2 -W 2 172.34.0.3 >/dev/null 2>&1; then
  echo "  node-1 gw-b ga yeta oladi (kutilgan)"
fi
echo "  lekin node-2 ning UDP portiga conntrack yozuvi yo'q → to'g'ridan-to'g'ri ishlamaydi"

echo
echo "═══ node-1 → node-2 (relay orqali) ═══"
$DOCKER exec cc01-n1 ping -6 -c 4 -W 3 "$A2" || true

echo
echo "═══ node-2 → node-1 ═══"
$DOCKER exec cc01-n2 ping -6 -c 3 -W 3 "$A1" || true

echo
echo "═══ qaysi yo'l ishlatilyapti ═══"
$DOCKER exec cc01-n1 grep -E "yo'l holati|sessiya o'rnatildi" /tmp/node-1.log | tail -5 || true

echo
echo "═══ relay statistikasi ═══"
$DOCKER logs cc01-cp 2>&1 | grep -E 'relay tayyor|node ulandi' || true
