# Environment Variables

`core-server` quyidagi muhit o'zgaruvchilarini o'qiydi.

## Majburiy

### `CC01_DOMAIN`
Barcha public tunnel hostnamelari uchun asosiy domen.
Masalan `example.com` bo'lsa, `demo` subdomaini `demo.example.com` bo'ladi.

### `CC01_TLS_CERT` va `CC01_TLS_KEY`
HTTPS listeneri uchun sertifikat va kalit fayllari yo'li.

### Avtorizatsiya — biri majburiy

Server avtorizatsiyasiz ishga tushmaydi (deny-by-default, `ARCHITECTURE.md` §1.5).
Quyidagilardan biri berilishi shart:

#### `CC01_ACCESS_ADDR`
`access-server` ning **ichki** gRPC porti, masalan `127.0.0.1:5081`.
Har bir tunnel so'rovi shu yerda avtorizatsiya qilinadi: token tekshiriladi,
subdomain egaligi aniqlanadi, tarif limitlari olinadi.

#### `CC01_AUTH_MODE=disabled`
Avtorizatsiyani **oshkora** o'chiradi: har qanday token qabul qilinadi va
subdomain egaligi tekshirilmaydi. Faqat lokal ishlab chiqish uchun — server
ishga tushganda ogohlantirish chiqaradi.

`CC01_AUTH_MODE=required` (yoki bo'sh) + `CC01_ACCESS_ADDR` — standart holat.

## Ixtiyoriy

| O'zgaruvchi | Standart | Vazifa |
| --- | --- | --- |
| `CC01_PUBLIC_PORT` | `80` | Public HTTP listener porti |
| `CC01_PUBLIC_TLS_PORT` | `443` | Public HTTPS listener porti |
| `CC01_EVENT_PORT` | `4321` | Klient boshqaruv kanali porti |
| `CC01_ACCESS_TIMEOUT` | `3s` | access-server chaqirig'i taymauti |
| `CC01_ACCESS_GRACE` | `15m` | access-server yiqilganda kesh'dagi ruxsat qancha vaqt yaroqli (fail-static) |

Vaqt qiymatlarini `30`, `90s`, `2m` ko'rinishida yozish mumkin — sof son
sekund deb qabul qilinadi.

## Fail-static xatti-harakati

`access-server` javob bermay qolsa (`ARCHITECTURE.md` §3.4.3):

| Holat | Natija |
| --- | --- |
| Mavjud tunnellar | Ishlashda davom etadi — ular AP'ga muhtoj emas |
| Yangi tunnel, kesh'da yaroqli yozuv bor | Qabul qilinadi (`CC01_ACCESS_GRACE` gacha) |
| Yangi tunnel, kesh'da yo'q | Rad etiladi: `SERVICE_UNAVAILABLE` |

## Hali sozlanmaydigan qiymatlar

`MaxConsPerTunnel = 24` — `core-server/config/config.go` da. Bu faqat
**zaxira** qiymat: avtorizatsiya ishlayotganda limit tarifdan keladi
(free 24, pro 128, enterprise 1024).

## Lokal ishga tushirish namunasi

```bash
# access-server bilan (to'liq rejim)
CC01_DOMAIN=cc01.test \
CC01_TLS_CERT=server/sample.crt CC01_TLS_KEY=server/sample.key \
CC01_PUBLIC_PORT=8080 CC01_PUBLIC_TLS_PORT=8443 \
CC01_ACCESS_ADDR=127.0.0.1:5081 \
  go run .

# avtorizatsiyasiz (faqat sinov uchun)
CC01_DOMAIN=cc01.test \
CC01_TLS_CERT=server/sample.crt CC01_TLS_KEY=server/sample.key \
CC01_PUBLIC_PORT=8080 CC01_PUBLIC_TLS_PORT=8443 \
CC01_AUTH_MODE=disabled \
  go run .
```

Klient tomondan token `-token` bayrog'i yoki `CC01_TOKEN` orqali beriladi:

```bash
cc01 -server 127.0.0.1:4321 -local 127.0.0.1:8099 -subdomain myapp -token cc01_live_…
```
