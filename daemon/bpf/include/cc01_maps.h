/* cc01 eBPF map'lari — YAGONA HAQIQAT MANBAI (DEV_SPEC §4.2).
 *
 * Bu fayldagi tuzilmalar Go tomonidagi nusxalari bilan BAYT-BAYT mos
 * kelishi shart. Mos kelmasa yadro xato bermaydi — u baytlarni
 * shunchaki boshqacha talqin qiladi va filtr jimgina noto'g'ri
 * ishlaydi. Shuning uchun Go tomonida o'lchamlar test bilan
 * qulflangan.
 */
#ifndef CC01_MAPS_H
#define CC01_MAPS_H

#include <linux/types.h>

/* Statistika hisoblagichlarining indekslari.
 *
 * Per-CPU massiv: har bir yadro o'z nusxasiga yozadi, ya'ni atomik
 * amal kerak emas va tez yo'lda qulf yo'q. Userspace o'qiyotganda
 * hammasini qo'shadi.
 */
enum cc01_stat {
    CC01_STAT_TOTAL = 0,      /* ko'rilgan hamma paket */
    CC01_STAT_PASS,           /* stackga o'tkazilgan */
    CC01_STAT_DROP_BLOCKLIST, /* blocklist bo'yicha tashlangan */
    CC01_STAT_DROP_MALFORMED, /* sarlavhasi buzuq */
    CC01_STAT_NOT_IPV6,       /* IPv6 emas — tegilmaydi */
    CC01_STAT_DROP_RATELIMIT, /* tezlik chegarasidan oshgan */
    CC01_STAT_AUTO_BLOCKED,   /* avtomatik blocklist'ga qo'shilgan */
    CC01_STAT_RL_MAP_FULL,    /* chelaklar map'i to'lgan — cheklov ishlamadi */
    CC01_STAT__MAX,
};

/* Konfiguratsiya: bitta yozuvli massiv.
 *
 * Map orqali beriladi, dasturga qattiq yozilmaydi: rejimni
 * o'zgartirish uchun dasturni qayta yuklash kerak bo'lmasin. Qayta
 * yuklash paytida esa paketlar filtrsiz o'tib ketardi.
 */
/* XDP filtrining sozlamasi.
 *
 * ⚠️ tc dasturining sozlamasi ALOHIDA tuzilma (cc01_policy_cfg).
 * Ilgari ular bittasini ulashardi va tc uchun maydon qo'shilganda
 * XDP tomonidagi Go nusxasi jimgina mos kelmay qoldi. Ikki dastur
 * mustaqil rivojlanadi — sozlamalari ham mustaqil bo'lsin.
 *
 * `packed` ATAYLAB ishlatilmaydi: maydonlar shundoq ham
 * to'ldirishsiz joylashadi, lekin packed ularni "moslashtirilmagan"
 * deb belgilab, atomik amallarni buzadi.
 */
struct cc01_config {
    __u32 flags;

    /* rate_pps — bitta manba /64 uchun soniyasiga ruxsat etilgan
     * paketlar. 0 = tezlik cheklanmaydi.
     *
     * Nega /64: IPv6'da bitta xost odatda butun /64 ni oladi, ya'ni
     * manzil bo'yicha cheklash hujumchiga cheklovni bir necha
     * milliard manzil bilan chetlab o'tish imkonini berardi.
     */
    __u32 rate_pps;

    /* burst — chelakning sig'imi (paketlarda). Qisqa portlashlarga
     * ruxsat beradi: aks holda oddiy TCP oynasi ham cheklovga
     * tushardi.
     */
    __u32 burst;

    /* auto_block_after — nechta tashlangandan keyin manba
     * blocklist'ga qo'shiladi. 0 = qo'shilmaydi.
     *
     * Blocklist eng arzon yo'l: keyingi paketlar token chelagini
     * hisoblamasdan tashlanadi.
     */
    __u32 auto_block_after;

    /* auto_block_ns — avtomatik blok qancha davom etadi. */
    __u64 auto_block_ns;
};

/* tc policy dasturining sozlamasi. */
struct cc01_policy_cfg {
    __u32 flags;

    /* policy_gen — qoidalar to'plamining AVLODI.
     *
     * Har bir qoida o'zgarishida userspace uni oshiradi. Conntrack
     * yozuvi qaysi avlodda yaratilganini eslab qoladi va avlodlar
     * mos kelmasa u eskirgan deb hisoblanadi.
     *
     * Busiz keshlangan hukm qoida o'chirilgandan keyin ham amal
     * qilib qolardi: taqiqlangan oqim ochiq qolardi va buni sezish
     * deyarli imkonsiz bo'lardi. Butun map'ni tozalash esa O(N) va
     * har bir o'zgarishda uni bajarib bo'lmaydi.
     */
    __u32 policy_gen;

    /* event_sample — har nechta tashlashdan bittasi hodisa sifatida
     * yuboriladi. 0 = hodisalar o'chirilgan, 1 = har biri.
     *
     * Deny-by-default siyosatida qoidalar to'liq yozilmagan bo'lsa
     * hamma paket tashlanadi va har biri uchun hodisa yuborish
     * kuzatuv vositasini xizmatni o'chirish vositasiga aylantirardi.
     */
    __u32 event_sample;

    /* mss_clamp — chiquvchi TCP SYN paketlaridagi MSS shu qiymatdan
     * oshmasligi ta'minlanadi. 0 = o'chirilgan.
     *
     * Nega kerak: overlay MTU 1280 (IPv6 minimumi), uchlar esa
     * yo'lni 1500 deb hisoblab kattaroq MSS kelishib oladi. Natijada
     * segmentlar sig'maydi va PMTU aniqlash ICMPv6 "Packet Too Big"
     * ga tayanadi — u esa ko'pincha filtrlangan bo'ladi. Oqibat:
     * ulanish o'rnatiladi, lekin katta uzatmalar QOTIB QOLADI.
     * Buni tashxislash juda qiyin.
     */
    __u16 mss_clamp;

    /* dscp — chiquvchi paketlarga qo'yiladigan DSCP (0..63).
     * 0 = tegilmaydi.
     */
    __u8  dscp;
    __u8  _pad;
};

/* F_ENFORCE — hukmni qo'llash. O'chirilgan bo'lsa (dry-run) hamma
 * paket o'tkaziladi, lekin hisoblagichlar to'ldiriladi.
 *
 * DEV_SPEC §4.4: har qanday yangi qoida avval dry-run'da ishlashi
 * shart. Ishlab chiqarish tarmog'ida noto'g'ri qoida butun trafikni
 * kesib qo'yishi mumkin.
 */
#define CC01_F_ENFORCE (1u << 0)

/* Blocklist yozuvi. */
/* Bu yerda ham packed yo'q: ikkala maydon 8 baytli va tabiiy
 * ravishda moslashgan. packed bo'lsa `hits` ustidagi atomik
 * qo'shish kompilyatsiya qilinmasdi.
 */
struct cc01_block {
    /* expires_ns — bpf_ktime_get_ns() shkalasida. 0 = muddatsiz.
     *
     * Yadro vaqti ishlatiladi, devor soati emas: XDP ichida devor
     * soatini o'qish qimmat va u sakrashi mumkin.
     */
    __u64 expires_ns;

    /* hits — nechta paket shu yozuv bo'yicha tashlangan.
     *
     * Atomik oshiriladi: yozuv hamma yadro uchun umumiy.
     */
    __u64 hits;
};

/* Tezlik cheklovi: manba /64 bo'yicha token chelak.
 *
 * Kalit — manzilning birinchi 8 bayti.
 */
struct cc01_rl_key {
    __u8 prefix[8];
};

struct cc01_rl_value {
    /* Chelak bir nechta yadrodan bir vaqtda o'zgartiriladi va
     * "o'qi-hisobla-yoz" ketma-ketligi atomik bo'lishi kerak.
     * Per-CPU map bu yerda yaramaydi: cheklov GLOBAL bo'lishi
     * kerak, aks holda u yadrolar soniga bo'linib ketardi va
     * bitta oqim (RSS tufayli bitta yadroga tushib) chegaraning
     * faqat N-dan bir qismini olardi.
     */
    struct bpf_spin_lock lock;

    /* tokens_milli — qolgan tokenlar, mingdan bir aniqlikda.
     *
     * Butun sonlarda ishlaymiz: BPF'da suzuvchi nuqta yo'q. Mingga
     * ko'paytirish qisqa oraliqlarda to'ldirish nolga
     * yaxlitlanmasligi uchun.
     */
    __u64 tokens_milli;

    /* last_ns — oxirgi to'ldirish vaqti (bpf_ktime_get_ns). */
    __u64 last_ns;

    /* dropped — shu manbadan nechta paket tashlangan. */
    __u64 dropped;
};

/* ─────────────── Policy (zero-trust ACL, tc_ingress) ───────────────
 *
 * Ikki bosqichli qidiruv, birlashtirilgan LPM kaliti EMAS.
 *
 * Hujjatning §4.2 dagi eskizi src, dst, port va protokolni bitta LPM
 * kalitiga birlashtiradi. Bu ishlamaydi: LPM prefiksi kalitning
 * BOSHIDAN sanaydi, ya'ni src bitlarini tashlab dst ga o'tib
 * bo'lmaydi — "istalgan src, aniq dst" qoidasini ifodalab bo'lmaydi.
 *
 * Buning o'rniga:
 *
 *   1. LPM trie:  src prefiksi  → identity (u32)
 *   2. Hash:      (identity, dport, proto) → hukm
 *
 * Bu N ta prefiks va M ta port qoidasi uchun N+M yozuv beradi,
 * birlashtirilgan kalitdagi N×M o'rniga.
 */

struct cc01_identity_key {
    /* prefixlen — LPM uchun: nechta bit ahamiyatli (0..128). */
    __u32 prefixlen;
    __u8  addr[16];
};

struct cc01_policy_key {
    __u32 identity;

    /* dport — 0 = istalgan port. */
    __u16 dport;

    /* proto — 0 = istalgan protokol. */
    __u8  proto;

    /* direction — CC01_DIR_*. Kirish va chiqish qoidalari BITTA
     * map'da yashaydi va faqat shu maydon bilan ajraladi.
     *
     * Ilgari bu joyda `_pad` turardi, ya'ni o'lcham o'zgarmadi.
     */
    __u8  direction;
};

#define CC01_DIR_INGRESS 0
#define CC01_DIR_EGRESS  1

struct cc01_policy_value {
    /* verdict — CC01_VERDICT_*. */
    __u8  verdict;
    __u8  _pad[3];

    /* rule_id — CP dagi qoida identifikatori (audit uchun). */
    __u32 rule_id;

    /* hits — atomik oshiriladi. */
    __u64 hits;
};

#define CC01_VERDICT_DROP  0
#define CC01_VERDICT_ALLOW 1

/* Identity qidiruvida hech narsa topilmasa ishlatiladi.
 *
 * Nol identity "noma'lum manba" degani va unga ham qoida yozish
 * mumkin — masalan hamma noma'lum manbaga ICMPv6 ga ruxsat berish.
 */
#define CC01_IDENTITY_UNKNOWN 0

/* Policy hisoblagichlari (tc dasturi uchun alohida). */
enum cc01_policy_stat {
    CC01_PSTAT_TOTAL = 0,
    CC01_PSTAT_ALLOW,
    CC01_PSTAT_DROP,
    CC01_PSTAT_DROP_MALFORMED,
    CC01_PSTAT_NOT_IPV6,
    CC01_PSTAT_NO_RULE,       /* qoida topilmadi — deny-by-default */
    CC01_PSTAT_EVENT_LOST,    /* ring buffer to'lgan — hodisa yo'qoldi */
    CC01_PSTAT_CT_HIT,        /* keshdan topildi — policy qidiruvi tejaldi */
    CC01_PSTAT_CT_MISS,       /* keshda yo'q yoki eskirgan */
    CC01_PSTAT_EGRESS_TOTAL,  /* chiquvchi paketlar */
    CC01_PSTAT_EGRESS_DROP,   /* chiqishda tashlangan */
    CC01_PSTAT_MSS_CLAMPED,   /* MSS kichraytirilgan */
    CC01_PSTAT__MAX,
};

/* Hodisa: nima uchun paket tashlandi.
 *
 * Hisoblagichlar "nechta" ni aytadi, hodisa esa "qaysi manzil, qaysi
 * qoida, qaysi port" ni. Nosozlikni tekshirishda aynan shu kerak:
 * "deny-by-default hamma narsani tashlayapti" xabari foydasiz, "node
 * X 5432-portga urinyapti va unga qoida yo'q" esa harakatga
 * chorlaydi.
 */
struct cc01_event {
    __u64 timestamp_ns;

    __u8  src[16];
    __u8  dst[16];

    __u16 dport;
    __u8  proto;

    /* verdict — CC01_VERDICT_*. Dry-run rejimida ham TASHLASH
     * yoziladi: hodisa "nima bo'lardi" ni ko'rsatadi.
     */
    __u8  verdict;

    __u32 identity;
    __u32 rule_id;

    /* dry_run — hukm qo'llandimi yoki faqat hisoblandimi. */
    __u8  dry_run;
    __u8  _pad[3];
};

/* ─────────────────── Conntrack (hukm keshi) ───────────────────
 *
 * Bu HUKM KESHI, holat kuzatuvchisi EMAS.
 *
 * Hujjatning §4.2 dagi eskizida `state` maydoni bor (NEW /
 * ESTABLISHED / CLOSING). Haqiqiy TCP holat mashinasini yadroda
 * to'g'ri qurish qiyin va uni yarim qurish xavfli: "ESTABLISHED"
 * deb belgilangan, lekin aslida tekshirilmagan oqim filtrni
 * chetlab o'tish yo'liga aylanardi.
 *
 * Shuning uchun bu yerda faqat hukm keshlanadi: birinchi paket
 * to'liq policy qidiruvidan o'tadi, keyingilari bitta hash
 * qidiruvi bilan cheklanadi.
 */
struct cc01_ct_key {
    __u8  src[16];
    __u8  dst[16];
    __u16 sport;
    __u16 dport;
    __u8  proto;

    /* direction — kirish va chiqish oqimlari alohida keshlanadi.
     *
     * Tuple'lar shundoq ham farq qiladi (manzillar o'rin
     * almashadi), lekin oshkora maydon niyatni ko'rsatadi va
     * kelajakdagi o'zgarishlarda tasodifiy to'qnashuvga yo'l
     * qo'ymaydi.
     */
    __u8  direction;
    __u8  _pad[2];
};

struct cc01_ct_value {
    __u64 last_seen_ns;
    __u64 packets;

    /* rule_id — qaysi qoida shu hukmni bergan (audit uchun). */
    __u32 rule_id;

    /* policy_gen — yozuv qaysi avlodda yaratilgan. Sozlamadagi
     * avloddan farq qilsa yozuv eskirgan.
     */
    __u32 policy_gen;

    __u8  verdict;
    __u8  _pad[7];
};

#endif /* CC01_MAPS_H */
