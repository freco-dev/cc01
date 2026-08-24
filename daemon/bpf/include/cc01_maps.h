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
    __u32 _pad;
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

#endif /* CC01_MAPS_H */
