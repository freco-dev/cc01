#!/bin/sh
# UDP hole punching: ikkita node har biri O'Z NAT'i ortida, lekin
# NAT'lar manba portini SAQLAYDI (cone NAT / endpoint-independent
# mapping).
#
#   net-public   172.35.0.0/24   cp+relay, gw-a:eth0, gw-b:eth0
#   net-a        172.35.1.0/24   gw-a:eth1, node-1
#   net-b        172.35.2.0/24   gw-b:eth1, node-2
#
# relay-demo dan farqi bitta qatorda: u yerda MASQUERADE ishlatiladi va
# Linux har bir manzil uchun boshqa tashqi port beradi (symmetric NAT) —
# u holda teshik ochib bo'lmaydi va relay yagona yo'l. Bu yerda esa
# SNAT portni majburan saqlaydi, ya'ni STUN aytgan manzil ikkala tomon
# uchun ham to'g'ri bo'lib qoladi.
#
# Kutilgan natija: ulanish relaydan boshlanadi, keyin ikkala tomon
# bir-birining public manziliga disco ping yuboradi, NAT'larda
# conntrack yozuvlari paydo bo'ladi va yo'l `direct-active` ga o'tadi.
set -e

DOCKER="docker --context desktop-linux"
IMAGE=cc01-cp-demo
PUB=cc01-pn-pub
NETA=cc01-pn-a
NETB=cc01-pn-b
TOKEN=demo-shared-secret-0123456789

cleanup() {
  $DOCKER rm -f cc01-pcp cc01-pgwa cc01-pgwb cc01-p1 cc01-p2 >/dev/null 2>&1 || true
  $DOCKER network rm $PUB $NETA $NETB >/dev/null 2>&1 || true
}
if [ -z "${KEEP:-}" ]; then
  trap cleanup EXIT
fi
cleanup

echo "── image ──"
$DOCKER build -q -t $IMAGE -f daemon/testdata/Dockerfile.cp . >/dev/null

echo "── tarmoqlar ──"
$DOCKER network create --subnet 172.35.0.0/24 $PUB  >/dev/null
$DOCKER network create --subnet 172.35.1.0/24 $NETA >/dev/null
$DOCKER network create --subnet 172.35.2.0/24 $NETB >/dev/null

# Cone NAT: overlay portidan chiqqan UDP uchun tashqi port MAJBURAN
# saqlanadi. Shunda mapping manzilga bog'liq bo'lmaydi va STUN bergan
# javob har qanday peer uchun to'g'ri bo'ladi.
gateway() {
  name=$1; pubip=$2; privnet=$3; privip=$4; subnet=$5
  $DOCKER run -d --name "$name" --network $PUB --ip "$pubip" \
    --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
    --entrypoint sh $IMAGE -c 'sleep infinity' >/dev/null
  $DOCKER network connect --ip "$privip" "$privnet" "$name"
  # Chiquvchi: overlay porti uchun tashqi port MAJBURAN saqlanadi.
  # Shunda mapping manzilga bog'liq bo'lmaydi va STUN bergan javob
  # har qanday peer uchun to'g'ri bo'ladi.
  $DOCKER exec "$name" iptables -t nat -A POSTROUTING \
    -s "$subnet" ! -d "$subnet" -p udp --sport 51820 \
    -j SNAT --to-source "$pubip:51820"
  $DOCKER exec "$name" iptables -t nat -A POSTROUTING \
    -s "$subnet" ! -d "$subnet" -j MASQUERADE

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

echo "── NAT shlyuzlari (port saqlanadi) ──"
gateway cc01-pgwa 172.35.0.2 $NETA 172.35.1.2 172.35.1.0/24
gateway cc01-pgwb 172.35.0.3 $NETB 172.35.2.2 172.35.2.0/24
echo "  gw-a → 172.35.0.2, gw-b → 172.35.0.3"

echo "── Control Plane + STUN + relay ──"
$DOCKER run -d --name cc01-pcp --network $PUB --ip 172.35.0.5 \
  --entrypoint cc01-cp $IMAGE \
  -listen :8443 -stun :3478 -relay 51821 -relay-endpoint 172.35.0.5:51821 \
  -tenant-net 'fd00:cc01:9a11::/64' -auth-token "$TOKEN" >/dev/null
sleep 2

KEY() { $DOCKER run --rm --entrypoint cc01d $IMAGE -genkey 2>/dev/null; }

echo "── nodelar ──"
node() {
  name=$1; net=$2; ip=$3; gw=$4; host=$5
  $DOCKER run -d --name "$name" --network "$net" --ip "$ip" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    --entrypoint sh $IMAGE -c 'sleep infinity' >/dev/null
  $DOCKER exec "$name" sh -c "ip route del default 2>/dev/null; ip route add default via $gw"
  $DOCKER exec -d "$name" sh -c "cc01d -key '$(KEY)' -cp 172.35.0.5:8443 \
    -cp-token '$TOKEN' -stun 172.35.0.5:3478 -hostname $host -listen 51820 -v \
    >/tmp/$host.log 2>&1"
}
node cc01-p1 $NETA 172.35.1.11 172.35.1.2 node-1
node cc01-p2 $NETB 172.35.2.12 172.35.2.2 node-2
sleep 4

ADDR() { $DOCKER exec "cc01-$1" grep -o 'addr=fd00:[^ ]*' "/tmp/$2.log" 2>/dev/null | head -1 | cut -d= -f2 | cut -d/ -f1; }
A1=$(ADDR p1 node-1); A2=$(ADDR p2 node-2)

echo
echo "═══ nodelar nimani aniqladi ═══"
$DOCKER exec cc01-p1 grep -E 'public manzil|relayga ulandi' /tmp/node-1.log || true
$DOCKER exec cc01-p2 grep -E 'public manzil|relayga ulandi' /tmp/node-2.log || true

echo
echo "═══ trafik boshlanadi (yo'l relaydan ochiladi) ═══"
$DOCKER exec cc01-p1 ping -6 -c 3 -W 3 "$A2"

echo
echo "═══ teshik ochilishini kutamiz ═══"
sleep 6

echo "── node-1 yo'l holati ──"
$DOCKER exec cc01-p1 cc01 peer list
echo "── node-2 yo'l holati ──"
$DOCKER exec cc01-p2 cc01 peer list

echo
echo "═══ yo'l qanday ko'tarildi ═══"
$DOCKER exec cc01-p1 sh -c "grep -E \"sessiya o'rnatildi|yo'l holati\" /tmp/node-1.log" || true

echo
echo "═══ NAT'lardagi teshiklar ═══"
echo "  gw-a:"
$DOCKER exec cc01-pgwa sh -c 'grep udp /proc/net/nf_conntrack | grep 172.35.0.3' | sed 's/^/    /' || true
echo "  gw-b:"
$DOCKER exec cc01-pgwb sh -c 'grep udp /proc/net/nf_conntrack | grep 172.35.0.2' | sed 's/^/    /' || true

echo
echo "═══ endi trafik to'g'ridan-to'g'ri ketyapti ═══"
$DOCKER exec cc01-p1 ping -6 -c 3 -W 3 "$A2"
