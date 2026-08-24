#!/bin/sh
# Control Plane bilan avtomatik mesh: uchta node QO'LDA PEER
# KONFIGURATSIYASIZ bir-birini topadi.
#
# Har bir node faqat CP manzilini biladi. Manzil, peerlar va
# marshrutlar — hammasi CP dan keladi.
set -e

DOCKER="docker --context desktop-linux"
NET=cc01-cp-demo
IMAGE=cc01-cp-demo
TOKEN=demo-shared-secret-0123456789

cleanup() {
  $DOCKER rm -f cc01-cp cc01-n1 cc01-n2 cc01-n3 cc01-bad cc01-impostor >/dev/null 2>&1 || true
  $DOCKER network rm $NET >/dev/null 2>&1 || true
}
# KEEP=1 — konteynerlarni qoldiradi (tekshirish uchun).
if [ -z "${KEEP:-}" ]; then
  trap cleanup EXIT
fi
cleanup

echo "── image quriladi ──"
$DOCKER build -q -t $IMAGE -f daemon/testdata/Dockerfile.cp . >/dev/null

echo "── tarmoq ──"
$DOCKER network create --subnet 172.32.88.0/24 $NET >/dev/null

echo "── Control Plane ──"
$DOCKER run -d --name cc01-cp --network $NET --ip 172.32.88.5 \
  -v "$PWD/daemon/testdata/policy.json":/policy.json:ro \
  --entrypoint cc01-cp $IMAGE \
  -listen :8443 -tenant-net 'fd00:cc01:c0de::/64' -auth-token "$TOKEN" \
  -tls-hosts 172.32.88.5 -policy /policy.json >/dev/null
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

for i in 1 2 3; do
  echo "── node $i ──"
  KEY=$($DOCKER run --rm --entrypoint cc01d $IMAGE -genkey 2>/dev/null)
  echo "$KEY" > "/tmp/cc01-node-$i.key"
  $DOCKER run -d --name "cc01-n$i" --network $NET --ip "172.32.88.1$i" \
    --cap-add NET_ADMIN --cap-add BPF --cap-add PERFMON \
    --device /dev/net/tun \
    --entrypoint cc01d $IMAGE \
    -key "$KEY" \
    -cp 172.32.88.5:8443 -cp-token "$TOKEN" -cp-pin "$PIN" \
    -state-dir /var/lib/cc01 -firewall \
    -hostname "node-$i" -listen 51820 >/dev/null
done

# Pin haqiqatan qo'riqlaydimi: noto'g'ri pin bilan ulanish
# TO'XTATILISHI kerak, aks holda pin bezak bo'lib qolardi.
echo "── noto'g'ri pin rad etiladimi ──"
BADPIN="sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
$DOCKER run -d --name cc01-bad --network $NET --ip 172.32.88.99 \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --entrypoint cc01d $IMAGE \
  -key "$($DOCKER run --rm --entrypoint cc01d $IMAGE -genkey 2>/dev/null)" \
  -cp 172.32.88.5:8443 -cp-token "$TOKEN" -cp-pin "$BADPIN" \
  -hostname node-bad -listen 51820 >/dev/null
sleep 3
if $DOCKER logs cc01-bad 2>&1 | grep -q 'pinga mos emas'; then
  echo "  ✔ ulanish rad etildi"
else
  echo "  ✘ NOTO'G'RI PIN O'TIB KETDI:"
  $DOCKER logs cc01-bad 2>&1 | tail -3
fi
$DOCKER rm -f cc01-bad >/dev/null 2>&1 || true

# Sertifikat haqiqatan himoya qiladimi: node-1 ning KALITI bilan,
# lekin BOSHQA sertifikat bilan ulanishga urinamiz. Token bizda bor
# (u umumiy sir), ya'ni eski modelda bu ishlagan bo'lardi.
echo "── o'g'irlangan token bilan node o'rniga o'tib bo'ladimi ──"
NODE1_KEY=$(cat /tmp/cc01-node-1.key 2>/dev/null || echo "")
if [ -n "$NODE1_KEY" ]; then
  $DOCKER run -d --name cc01-impostor --network $NET --ip 172.32.88.98 \
    --cap-add NET_ADMIN --device /dev/net/tun \
    --entrypoint cc01d $IMAGE \
    -key "$NODE1_KEY" -cp 172.32.88.5:8443 -cp-token "$TOKEN" -cp-pin "$PIN" \
    -state-dir /var/lib/cc01 -hostname impostor -listen 51820 >/dev/null
  sleep 4
  if $DOCKER logs cc01-impostor 2>&1 | grep -q "sertifikati bog'langanidan farq"; then
    echo "  ✔ rad etildi — sertifikat mos kelmadi"
  else
    echo "  ✘ O'TIB KETDI:"
    $DOCKER logs cc01-impostor 2>&1 | tail -3
  fi
  $DOCKER rm -f cc01-impostor >/dev/null 2>&1 || true
fi

echo "── peerlar topilishini kutamiz ──"
sleep 6

echo
echo "═══ CP ro'yxati ═══"
$DOCKER logs cc01-cp 2>&1 | grep 'ro.yxatdan o.tdi' || true

echo
echo "═══ node 1 nimani ko'rdi ═══"
$DOCKER logs cc01-n1 2>&1 | grep -E 'tayyor|peer qo' || true

ADDR() { $DOCKER logs "cc01-n$1" 2>&1 | grep -o 'addr=fd00:[^ ]*' | head -1 | cut -d= -f2 | cut -d/ -f1; }
A1=$(ADDR 1); A2=$(ADDR 2); A3=$(ADDR 3)
echo
echo "═══ CP bergan manzillar ═══"
echo "  node-1: $A1"
echo "  node-2: $A2"
echo "  node-3: $A3"

echo
echo "═══ node-1 → node-2 ═══"
$DOCKER exec cc01-n1 ping -6 -c 3 -W 3 "$A2"

echo
echo "═══ node-1 → node-3 ═══"
$DOCKER exec cc01-n1 ping -6 -c 3 -W 3 "$A3"

echo
echo "═══ node-3 → node-2 ═══"
$DOCKER exec cc01-n3 ping -6 -c 2 -W 3 "$A2"

echo
echo "═══ cc01 status (node-1) ═══"
$DOCKER exec cc01-n1 cc01 status

echo
echo "═══ cc01 peer list (node-1) ═══"
$DOCKER exec cc01-n1 cc01 peer list

echo
echo "═══ cc01 doctor (node-1) ═══"
$DOCKER exec cc01-n1 cc01 doctor

echo
echo "═══ cc01 firewall (node-1) ═══"
A2_ADDR=$($DOCKER exec cc01-n2 cc01 status | awk '/manzil/ {print $2}' | cut -d/ -f1)

echo "── CP dan kelgan qoidalar ──"
$DOCKER exec cc01-n1 cc01 firewall list

echo "── mesh ichidagi ICMPv6 (CP ruxsat bergan) ──"
$DOCKER exec cc01-n1 cc01 firewall test --src "$A2_ADDR" --proto icmpv6

echo "── SSH (CP taqiqlagan) ──"
$DOCKER exec cc01-n1 cc01 firewall test --src "$A2_ADDR" --proto tcp --port 22

echo "── mesh tashqarisi (qoida yo'q) ──"
$DOCKER exec cc01-n1 cc01 firewall test --src 2a0e:dead::1 --proto icmpv6

# Lokal qoidalar CP diapazonidan (1000000+) PASTDA yashaydi va CP
# yangilanishida o'chirilmaydi.
echo "── lokal qoida CP qoidalari bilan yonma-yon ──"
$DOCKER exec cc01-n1 cc01 firewall add --allow --src 2a0e:dead::1/128 --proto icmpv6 >/dev/null
$DOCKER exec cc01-n1 cc01 firewall list

echo
echo "═══ marshrut jadvali 51820 (node-1) ═══"
$DOCKER exec cc01-n1 ip -6 route show table 51820

echo
echo "═══ cc01 down → up sikli (node-1) ═══"
$DOCKER exec cc01-n1 cc01 down
echo "  interfeys:  $($DOCKER exec cc01-n1 ip -6 addr show cc0 2>&1 | head -1 || true)"
echo "  marshrutlar: $($DOCKER exec cc01-n1 ip -6 route show table 51820 | wc -l) ta"
$DOCKER exec cc01-n1 cc01 status

echo
echo "  --- qayta ko'tarish ---"
$DOCKER exec cc01-n1 cc01 up
sleep 3
echo "  --- ping6 qayta ishlayaptimi ---"
$DOCKER exec cc01-n1 ping -6 -c 2 -W 3 "$A2"
