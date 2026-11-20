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
`CC01_ACCESS_ADDR` `host:port` ko'rinishida bo'lishi shart (port majburiy).

### Edge ↔ access-server kanali: mTLS (`DEV_SPEC` S-11, A-S5)

| O'zgaruvchi | Vazifa |
| --- | --- |
| `CC01_ACCESS_TLS_CA` | PEM to'plami — AP server sertifikatini tekshiradigan **yagona** ildizlar. Tizim ildizlari hech qachon ishlatilmaydi |
| `CC01_ACCESS_TLS_CERT` | Edge klient sertifikati (PEM, ECDSA P-256 yoki RSA). Subject CN — edge identifikatori (AP allowlist'ida bo'lishi shart), `clientAuth` EKU majburiy. Oraliq CA bo'lsa zanjir shu faylga qo'shiladi |
| `CC01_ACCESS_TLS_KEY` | Klient sertifikati kaliti (PEM: PKCS#8, PKCS#1 yoki SEC 1) |
| `CC01_ACCESS_TLS_SERVER_NAME` | Ixtiyoriy. AP sertifikatida tekshiriladigan nom (DNS yoki IP SAN). Standart: `CC01_ACCESS_ADDR` ning host qismi |
| `CC01_ACCESS_TLS_MIN` | Ixtiyoriy: `1.3` (sukut) yoki `1.2`. **`1.2` faqat loopback'dagi AP uchun** — macOS'da .NET server tomonda TLS 1.3 ni qo'llamaydi (SecureTransport), lokal `dotnet run` AP faqat TLS 1.2 da gaplashadi. Tarmoq manzilida `1.2` — ishga tushmaydi; `access.Dial` ham uni 1.3 ga ko'taradi |

Qoidalar:

- `CA`/`CERT`/`KEY` dan **birortasi** berilsa mTLS yoqiladi va unda
  **uchalasi ham** majburiy. Fayllar ishga tushishda o'qiladi va
  tekshiriladi: fayl yo'q, PEM noto'g'ri, kalit sertifikatga mos emas,
  sertifikatda CN yoki `clientAuth` EKU yo'q, muddati tugagan — server ishga
  tushmaydi, xato tegishli o'zgaruvchini nomlaydi. TLS 1.3 majburiy.
- mTLS'siz (shifrsiz) ulanish **faqat loopback** `CC01_ACCESS_ADDR` uchun
  ruxsat etiladi: `127.0.0.0/8`, `::1` yoki `localhost`. Boshqa har qanday
  manzilda server ishga tushmaydi:
  `CC01_ACCESS_ADDR loopback emas va mTLS sozlanmagan …`. `access.Dial` ham
  buni ikkinchi marta tekshiradi.
- `CC01_ACCESS_TLS_SERVER_NAME` yoki `CC01_ACCESS_TLS_MIN` yolg'iz (mTLS'siz)
  berilsa — xato (chala sozlama).
- `CC01_AUTH_MODE=disabled` da AP'ga ulanish yo'q — TLS o'zgaruvchilari
  e'tiborsiz qoldiriladi.
- AP edge'ni klient sertifikatining CN'i bo'yicha taniydi (allowlist) va
  `clientAuth` EKU talab qiladi; edge tomonida boshqa sozlama yo'q.
- **Sertifikatni almashtirish (rotation) uchun edge qayta ishga
  tushiriladi** — fayllar faqat ishga tushishda o'qiladi (hot reload yo'q).
  Klient sertifikati muddati ishga tushish log'ida ko'rinadi.

Ishga tushishda bitta qator qaysi rejim faolligini aytadi:

```
[access] mTLS: CA=<fayl>, CN=<edge CN>, server_name=<nom>, TLS ≥ 1.3, sertifikat muddati <vaqt> (…)
[access] plaintext (loopback): 127.0.0.1:5081
```

AP sertifikati tekshiruvdan o'tmasa (begona CA, nom mos emas) yoki AP edge
sertifikatini rad etsa, bu **rad javobi emas**, tarmoq xatosi: yangi
tunnellar fail-static yo'liga tushadi (`SERVICE_UNAVAILABLE` yoki kesh),
ochiq tunnellar yopilmaydi (`[tunnel-renew-failed]`).

## Ixtiyoriy

| O'zgaruvchi | Standart | Vazifa |
| --- | --- | --- |
| `CC01_PUBLIC_PORT` | `80` | Public HTTP listener porti |
| `CC01_PUBLIC_TLS_PORT` | `443` | Public HTTPS listener porti |
| `CC01_EVENT_PORT` | `4321` | Klient boshqaruv kanali porti |
| `CC01_ACCESS_TIMEOUT` | `3s` | access-server chaqirig'i taymauti. Musbat bo'lishi shart; yangilash yoqilgan bo'lsa `6s + CC01_ACCESS_RENEW + CC01_ACCESS_TIMEOUT < 60s` (pastga qarang), aks holda server ishga tushmaydi |
| `CC01_ACCESS_GRACE` | `15m` | access-server yiqilganda kesh'dagi ruxsat qancha vaqt yaroqli (fail-static) — faqat **yangi** tunnellar uchun |
| `CC01_ACCESS_RENEW` | `30s` | Ochiq tunnel ruxsatini AP'da qayta tekshirish oralig'i (lease yangilanishi). `0` — o'chirish (kill switch); aks holda `1s`..`50s` va `CC01_ACCESS_TIMEOUT` bilan birga 60 s kafolatiga sig'ishi shart, boshqa qiymatda server ishga tushmaydi. `CC01_AUTH_MODE=disabled` da doim `0` |
| `CC01_ACCESS_RENEW_DENY` | `close` | Yangilashda qat'iy rad javobi kelganda: `close` — tunnel yopiladi, `log` — faqat `[tunnel-revoke-dryrun]` yoziladi (dry run, rollout uchun) |
| `CC01_USAGE_INTERVAL` | `60s` | Foydalanish oynasi uzunligi va AP'ga hisobot (`ReportUsage`) oralig'i. `0` — o'chirish; aks holda `5s`..`300s`, butun sekund — boshqa qiymatda server ishga tushmaydi. `CC01_AUTH_MODE=disabled` da doim `0` (pastga qarang) |

Vaqt qiymatlarini `30`, `90s`, `2m` ko'rinishida yozish mumkin — sof son
sekund deb qabul qilinadi.

### Ochiq tunnel yangilanishi (`CC01_ACCESS_RENEW`)

Edge har bir ochiq tunnel uchun `AuthorizeTunnel` ni `renewal=true` bilan
davriy qayta chaqiradi. Oraliq `R = min(CC01_ACCESS_RENEW, lease_ttl/2)`,
har kutish `R·U[0.8,1]` (jitter faqat kamaytiradi). Birinchi yangilash
grant olingan paytga (RPC boshlanishi) bog'langan, keshdagi natija ham
ko'pi bilan `R` yangi hisoblanadi (`min(CC01_ACCESS_RENEW, lease_ttl/2)`)
— shuning uchun tarif o'zgarishi, muddat tugashi, token bekor qilinishi va
hisob to'xtatilishi ochiq tunnelga yetib boradi:

| Holat | Chegara | Standart |
| --- | --- | --- |
| Edge→AP kanali tayyor (odatiy holat) | `≤ R + CC01_ACCESS_TIMEOUT` | 30 + 3 = **33 s** |
| AP yiqilib qaytgandan keyin (o'zgarish AP qaytgan zahoti qilingan) | `≤ 6 s + R + CC01_ACCESS_TIMEOUT` | 6 + 30 + 3 = **39 s** |

`6 s` — AP yana erishiladigan bo'lgandan edge'ning gRPC kanali qayta
ulanguncha eng uzoq kutish (cheklangan backoff: urinish taymauti 3 s +
pauza ≤ 2 s·1.2). AP yo'q paytda kafolat yo'q — bu fail-static (pastda).
Server ishga tushganda `6s + CC01_ACCESS_RENEW + CC01_ACCESS_TIMEOUT < 60s`
ni tekshiradi (`R ≤ CC01_ACCESS_RENEW`), aks holda ishga tushmaydi:
masalan `CC01_ACCESS_RENEW=50s` faqat `CC01_ACCESS_TIMEOUT < 4s` bilan
qabul qilinadi.

Rad javobi (yangilashda ham, ochilishda ham) shu tokenga shu nomni hali
berishi mumkin bo'lgan barcha kesh yozuvlarini o'chiradi: token
darajasidagi rad (`TOKEN_*`, `PLAN_SUSPENDED`, `EMAIL_NOT_VERIFIED`) —
tokenning hamma yozuvlarini, boshqalari — shu subdomain (shu jumladan
klient bo'sh subdomain bilan ochgan, AP aynan shu nomni bergan yozuv) va
shu custom domain yozuvlarini. Rad javobidan oldin boshlangan va kechroq
qaytgan grant keshga yozilmaydi, shuning uchun rad etilgan token keshdan
(fail-static orqali ham) qayta ochila olmaydi.

Tunnelni faqat quyidagi rad javoblari yopadi (allowlist):
`TOKEN_INVALID`, `TOKEN_REVOKED`, `TOKEN_EXPIRED`, `PLAN_SUSPENDED`,
`SUBDOMAIN_NOT_OWNED`. Klient yopilishdan oldin
`TunnelOpened{error_code, error_message}` freymini oladi. Boshqa har qanday
kod (noma'lum, `UNSPECIFIED`, `SUBDOMAIN_BUSY`, `QUOTA_*`) log'ga yoziladi
va tunnel saqlanadi.

`max_conns_per_tunnel` jonli qo'llanadi (faqat yangi ulanishlarga),
`max_tunnels` esa faqat ochilishda va shu edge doirasida tekshiriladi
(`QUOTA_TUNNELS_EXCEEDED`). Tarif pasaytirilsa mavjud tunnel va ulanishlar
uzilmaydi.

Log yozuvlari (token hech qachon yozilmaydi):

| Yozuv | Ma'nosi |
| --- | --- |
| `[tunnel-limits] <id> plan=<p> max_conns=<n>` | Yangi limitlar qo'llandi (faqat o'zgarganda) |
| `[tunnel-renew-failed] <id> err=…` | AP javob bermadi yoki yopmaydigan kod qaytardi — tunnel saqlanadi |
| `[tunnel-revoked] <id> code=<c>` | Allowlist'dagi rad javobi — tunnel yopildi |
| `[tunnel-revoke-dryrun] <id> code=<c>` | `CC01_ACCESS_RENEW_DENY=log`: yopilishi kerak edi, lekin yopilmadi |

Favqulodda holatda: `CC01_ACCESS_RENEW_DENY=log` (yopishni to'xtatadi,
yangi limitlar qo'llanishda davom etadi) yoki `CC01_ACCESS_RENEW=0`
(yangilashni butunlay o'chiradi).

Tarifni o'zgartirish runbook'i (`make ap-set-plan`, audit so'rovi, orqaga
qaytarish) — `docs/DEV_SPEC.md` §6.4. Uchidan uchiga tekshiruv va o'lchov:
`make plan-demo` (AP, edge va klientni lokal ko'taradi; tarif o'zgarishidan
`[tunnel-limits]` gacha vaqtni o'lchaydi, 60 s dan oshsa yiqiladi).

### Foydalanish hisoboti (`CC01_USAGE_INTERVAL`)

Edge har ochiq tunnelning trafigini o'lchaydi va vaqt oynalari bilan
`AccessInternalService.ReportUsage` orqali AP'ga yuboradi (DEV_SPEC §8).
AP oynalarni `(tunnel_id, window_start)` bo'yicha idempotent saqlaydi.

Har oynada (`UsageWindow`):

| Maydon | Ma'nosi |
| --- | --- |
| `tenant_id` | Tenant slug (`Grant.tenant_id`) |
| `tunnel_id` | Tunnel **nusxasi** ID'si: `<host>:<port>/<16 hex>` (masalan `demo.cc01.uz:80/3f9c0a7e12b4d655`), ≤ 128 belgi. Xuddi shu nom bilan qayta ochilgan tunnel yangi ID oladi. Log'larda (`[tunnel-opened] <id>` va h.k.) va `TunnelOpened.tunnel_id` da ham shu |
| `window_start`, `window_end` | Unix sekund, `[start, end)`, `end > start` |
| `bytes_in` | Ommaviy tomondan lokal xizmatga yetkazilgan baytlar (HTTP: Host'ni aniqlash uchun oldindan o'qilgan bufer ham; TLS'dan keyingi ochiq baytlar) |
| `bytes_out` | Lokal xizmatdan ommaviy klientga qaytgan baytlar |
| `connections` | Qabul qilingan ommaviy ulanishlar (navbatga qo'yilgan / ko'priklangan) |
| `rejected` | `max_conns` limiti tufayli rad etilganlar (`ConnectionReceived{rate_limited}`) |

Oynalar:

- **Devor soatiga tekislangan**: chegaralar unix vaqt `I` ga karrali
  bo'lgan paytlarda (`I = CC01_USAGE_INTERVAL`; `60s` da — har daqiqa
  boshida). Har chegarada **har** ochiq tunnel uchun oyna kesiladi —
  trafiksizi uchun ham (AP tunnel-soatlarni oyna davomiyligidan oladi).
- Birinchi oyna ochilish sekundidan (pastga yaxlitlangan) keyingi
  chegaragacha, oxirgisi oxirgi chegaradan yopilish sekundigacha (pastga
  yaxlitlangan) — qisman oynalar. Bitta tunnelning oynalari uzluksiz va
  ustma-ust tushmaydi.
- **< 1 s oynalar**: tunnel chegara sekundining o'zida ochilsa, o'sha
  chegarada oyna kesilmaydi — trafik keyingi oynaga qo'shiladi. Yopilish
  oxirgi chegara bilan bir sekundga tushsa (yoki tunnel bir sekund ichida
  ochilib-yopilsa), yakuniy oyna 1 s ga cho'ziladi (`[s, s+1)`) — oxirgi
  baytlar yo'qolmaydi. Natijada davomiylik sekund aniqligida (±1 s).
- Yakuniy oyna tunnel to'liq yopilgandan keyin kesiladi (ko'prik
  nusxalari tugashi kutiladi) — yopilish paytida o'tgan baytlar ham
  hisoblanadi.

Yuborish:

- Oynalar xotiradagi navbatga tushadi (≤ 10 000) va har chegarada
  ≤ 500 lik bo'laklarda, tartib bilan yuboriladi (RPC taymauti —
  `CC01_ACCESS_TIMEOUT`). AP `accepted` qaytaradi: navbat boshidan
  shuncha oyna o'chiriladi, qolgani keyingi tikda qayta yuboriladi.
  Yopilgan tunnelning yakuniy oynasi keyingi chegarada (≤ `I`) ketadi.
- AP yo'q / xato: hamma oyna navbatda qoladi va keyingi tikda qayta
  yuboriladi. **AP yo'qligi tunnellarga hech qanday ta'sir qilmaydi**
  (fail-static, limitlar va yangilash o'zgarmaydi).
- Navbat to'lsa **eng eski** oynalar tashlanadi (`[usage-dropped]`).
  60 s oynada 10 000 oyna ≈ 166 tunnel·soat AP'siz.
- To'xtash (SIGINT → `Stop`): ochiq tunnellar uchun hozirgacha oyna
  kesiladi va navbat ≤ 5 s ichida best-effort yuboriladi.
- **Edge qulasa yoki qayta ishga tushsa navbat yo'qoladi** (diskka
  yozilmaydi): yetkazish "ko'pi bilan bir marta" — yuborilmagan oynalar
  hisobga kirmaydi. Dublikat esa bo'lmaydi: AP idempotent.
- `CC01_USAGE_INTERVAL=0` yoki `CC01_AUTH_MODE=disabled` — hisobot
  o'chiq (ishga tushishda ogohlantirish), tunnellar odatdagidek ishlaydi.

Log yozuvlari (token yozilmaydi):

| Yozuv | Ma'nosi |
| --- | --- |
| `[usage-reported] windows=<N> accepted=<M>` | Shu tikda N oyna yuborildi, AP M tasini qabul qildi (faqat N > 0 bo'lganda) |
| `[usage-report-failed] queued=<N> err=…` | AP javob bermadi yoki xato qaytardi; N oyna navbatda qoldi, keyingi tikda qayta |
| `[usage-dropped] n=<N> (navbat to'la)` | Navbat to'ldi — eng eski N oyna tashlandi |

Ishga tushishda: `[usage] har 1m0s da oyna kesiladi va AP'ga yuboriladi …`
yoki `⚠️  foydalanish hisoboti O'CHIQ (CC01_USAGE_INTERVAL=0) …`.

Demo uchun qisqa oyna: `CC01_USAGE_INTERVAL=5s` — oynalar har 5 s da
(:00, :05, :10, …) kesiladi va yuboriladi.

## Fail-static xatti-harakati

`access-server` javob bermay qolsa (`ARCHITECTURE.md` §3.4.3):

| Holat | Natija |
| --- | --- |
| Mavjud tunnellar | Ishlashda davom etadi — trafik AP'ga muhtoj emas |
| Ochiq tunnel, AP javob bermadi | Oxirgi limitlar bilan cheksiz davom etadi; `min(R, 10 s)` dan keyin qayta uriniladi (`[tunnel-renew-failed]`) |
| Ochiq tunnel, qat'iy rad (allowlist) | `≤ R + CC01_ACCESS_TIMEOUT` (standart 33 s) ichida yopiladi (`CC01_ACCESS_RENEW_DENY=log` bo'lsa — faqat log). Klient boshqaruv kanalini o'qimasa, yopilish xabari yana ≤ 5 s kutadi (pastga qarang) |
| AP qaytdi | Kanal ≤ 6 s ichida qayta ulanadi; shu paytgacha yangi tunnellar keshdan yoki `SERVICE_UNAVAILABLE` |
| Foydalanish oynalari | Navbatda (≤ 10 000) kutadi va keyingi tikda qayta yuboriladi (`[usage-report-failed]`) |
| Yangi tunnel, kesh'da yaroqli yozuv bor | Qabul qilinadi (`CC01_ACCESS_GRACE` gacha) |
| Yangi tunnel, kesh'da yo'q | Rad etiladi: `SERVICE_UNAVAILABLE` |

## Hali sozlanmaydigan qiymatlar

`MaxConsPerTunnel = 24` — `core-server/config/config.go` da. Bu faqat
**zaxira** qiymat: avtorizatsiya ishlayotganda limit tarifdan keladi
(free 24, pro 128, enterprise 1024).

Kodda qat'iy belgilangan taymautlar:

| Qiymat | Joyi | Vazifa |
| --- | --- | --- |
| 5 s | `tunnel.EventWriteTimeout` | Boshqaruv kanaliga bitta freym yozish muddati. Klient 5 s ichida o'qimasa kanal yopiladi va tunnel odatiy yo'l bilan yopiladi; yozish tunnel qulfi ostida bajarilmaydi |
| 3 s | `publicHostTimeout` (`cc01.go`) | Public ulanishdan Host (TLS'da qo'l siqish ham) o'qish va 400/404 javobi. Ko'prikka ulangan ulanishda muddat olib tashlanadi |
| 10 000 / 500 | `usage.DefaultQueueMax` / `usage.DefaultBatchMax` | Foydalanish navbati (eng eskisi tashlanadi) va bitta `ReportUsage` dagi oynalar |
| 5 s | `usageFlushTimeout` (`usage.go`) | To'xtashda navbatni AP'ga yuborish uchun umumiy muddat |
| ≤ 6 s | `config.AccessReconnectMax` | AP qayta erishiladigan bo'lgandan edge→AP gRPC kanali qayta ulanguncha (backoff 1 s × 1.6, ≤ 2 s, jitter 0.2; urinish taymauti 3 s) |

## Lokal ishga tushirish namunasi

```bash
# access-server bilan (to'liq rejim)
CC01_DOMAIN=cc01.test \
CC01_TLS_CERT=server/sample.crt CC01_TLS_KEY=server/sample.key \
CC01_PUBLIC_PORT=8080 CC01_PUBLIC_TLS_PORT=8443 \
CC01_ACCESS_ADDR=127.0.0.1:5081 \
  go run .

# access-server boshqa hostda — mTLS majburiy (make dev-certs → .dev-certs/)
CC01_DOMAIN=cc01.test \
CC01_TLS_CERT=server/sample.crt CC01_TLS_KEY=server/sample.key \
CC01_PUBLIC_PORT=8080 CC01_PUBLIC_TLS_PORT=8443 \
CC01_ACCESS_ADDR=localhost:5081 \
CC01_ACCESS_TLS_CA=../.dev-certs/ca.pem \
CC01_ACCESS_TLS_CERT=../.dev-certs/edge.pem \
CC01_ACCESS_TLS_KEY=../.dev-certs/edge.key \
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
