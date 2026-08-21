#!/bin/sh
# Ikkita konteyner o'rtasida haqiqiy shifrlangan overlay quradi va
# ping6 bilan tekshiradi.
#
# Har bir konteyner o'z tarmoq namespace'ida, ya'ni TUN interfeyslari
# va marshrutlari bir-biriga aralashmaydi — trafik haqiqatan UDP
# orqali, shifrlangan holda o'tadi.
set -e

DOCKER="docker --context desktop-linux"
NET=cc01-mesh-demo
IMAGE=cc01-daemon-demo

cleanup() {
  $DOCKER rm -f cc01-a cc01-b >/dev/null 2>&1 || true
  $DOCKER network rm $NET >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "── image quriladi ──"
$DOCKER build -q -t $IMAGE -f daemon/testdata/Dockerfile . >/dev/null

echo "── tarmoq yaratiladi ──"
$DOCKER network create --subnet 172.31.77.0/24 $NET >/dev/null

echo "── kalitlar ──"
KEY_A=$($DOCKER run --rm $IMAGE -genkey 2>/tmp/pub_a)
PUB_A=$(sed 's/^public: //' /tmp/pub_a)
KEY_B=$($DOCKER run --rm $IMAGE -genkey 2>/tmp/pub_b)
PUB_B=$(sed 's/^public: //' /tmp/pub_b)
echo "  A: $PUB_A"
echo "  B: $PUB_B"

ADDR_A=fd00:cc01:beef::1
ADDR_B=fd00:cc01:beef::2

echo "── node A ──"
$DOCKER run -d --name cc01-a --network $NET --ip 172.31.77.10 \
  --cap-add NET_ADMIN --device /dev/net/tun $IMAGE \
  -key "$KEY_A" -addr "$ADDR_A/128" -listen 51820 \
  -peer-key "$PUB_B" -peer-endpoint 172.31.77.11:51820 \
  -peer-allowed "$ADDR_B/128" >/dev/null

echo "── node B ──"
$DOCKER run -d --name cc01-b --network $NET --ip 172.31.77.11 \
  --cap-add NET_ADMIN --device /dev/net/tun $IMAGE \
  -key "$KEY_B" -addr "$ADDR_B/128" -listen 51820 \
  -peer-key "$PUB_A" -peer-endpoint 172.31.77.10:51820 \
  -peer-allowed "$ADDR_A/128" >/dev/null

sleep 3

echo
echo "═══ A dan B ga ping6 ═══"
$DOCKER exec cc01-a ping -6 -c 4 -W 3 "$ADDR_B"

echo
echo "═══ B dan A ga ping6 ═══"
$DOCKER exec cc01-b ping -6 -c 2 -W 3 "$ADDR_A"

echo
echo "═══ node A logi ═══"
$DOCKER logs cc01-a 2>&1 | tail -5
