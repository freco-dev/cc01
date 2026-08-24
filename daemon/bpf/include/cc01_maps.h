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
/* `packed` ATAYLAB ishlatilmaydi.
 *
 * Maydonlar shundoq ham to'ldirishsiz joylashadi (ikkita 4 baytlik),
 * ya'ni packed hech narsa o'zgartirmaydi. Lekin u maydonlarni
 * "moslashtirilmagan" deb belgilaydi va bu atomik amallarni buzadi
 * — clang buni xato bilan to'xtatadi. `_pad` esa oshkora: Go
 * tomonidagi nusxa bilan solishtirish oson bo'lsin.
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

#endif /* CC01_MAPS_H */
