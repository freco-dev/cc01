// SPDX-License-Identifier: GPL-2.0
/* cc01 XDP filtri (DEV_SPEC §4.3).
 *
 * Hozircha ikkita bosqich: sanity va blocklist. Qolganlari —
 * rate limit, conntrack, policy — shu skelet ustiga qo'shiladi.
 *
 * # Nega XDP
 *
 * XDP paketni yadro tarmoq stekiga KIRISHIDAN oldin ko'radi, ya'ni
 * `sk_buff` hatto yaratilmaydi. Hujum paytida tashlanadigan paket
 * uchun bu eng arzon nuqta.
 *
 * # Chegaralar
 *
 * Verifier har bir xotira murojaatini isbotlashni talab qiladi:
 * `data_end` bilan solishtirmasdan biror baytga tegib bo'lmaydi.
 * Shuning uchun har bir sarlavhadan oldin chegara tekshiruvi bor va
 * ular olib tashlanmaydi — ular ortiqcha emas, dasturning
 * yuklanishi uchun shart.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "cc01_maps.h"

char LICENSE[] SEC("license") = "GPL";

/* Statistika. Per-CPU: tez yo'lda atomik amal bo'lmasligi uchun. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, CC01_STAT__MAX);
} cc01_stats SEC(".maps");

/* Konfiguratsiya: bitta yozuv. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct cc01_config);
    __uint(max_entries, 1);
} cc01_config_map SEC(".maps");

/* Blocklist: manba IPv6 manzili bo'yicha.
 *
 * LRU emas, oddiy hash: yozuvlarni operator va userspace boshqaradi
 * va ular o'z-o'zidan siqib chiqarilmasligi kerak. LRU bo'lsa hujum
 * paytida yangi yozuvlar eskilarini siqib chiqarardi — aynan
 * hujumchi xohlagan natija.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);
    __type(value, struct cc01_block);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cc01_blocklist SEC(".maps");

/* Tezlik cheklovi chelaklari.
 *
 * LRU_HASH emas, oddiy HASH: yadro `bpf_spin_lock` ni faqat HASH va
 * ARRAY uchun qabul qiladi (LRU'da `map create: operation not
 * supported`). Qulf esa kerak — token chelagi "o'qi-hisobla-yoz"
 * ketma-ketligi va u bir nechta yadrodan bir vaqtda bajariladi.
 *
 * ⚠️ Bunda avtomatik evikatsiya yo'q: eskirgan chelaklarni userspace
 * tozalaydi (`Filter.Sweep`). Tozalanmasa map to'lib qoladi va yangi
 * manbalar cheklovsiz o'tib ketardi — aynan hujumchi xohlagan
 * natija.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct cc01_rl_key);
    __type(value, struct cc01_rl_value);
    __uint(max_entries, 65536);
} cc01_ratelimit SEC(".maps");

/* Hodisalar halqasi. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cc01_xdp_events SEC(".maps");

/* AF_XDP soketlari: cc01 datapath'ini userspace'ga zero-copy
 * yetkazish uchun (DEV_SPEC §4.3, Stage 4).
 *
 * Map BO'SH bo'lsa `bpf_redirect_map` fallback qiymatini qaytaradi
 * va biz XDP_PASS beramiz — ya'ni paket odatdagi yadro steki orqali
 * cc01d ning UDP soketiga boradi. Shu sababdan bu yo'lni yoqish
 * xavfsiz: AF_XDP soketi ulanmagan bo'lsa hech narsa o'zgarmaydi.
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} cc01_xsks SEC(".maps");

static __always_inline void stat_inc(__u32 index)
{
    __u64 *counter = bpf_map_lookup_elem(&cc01_stats, &index);
    if (counter)
        (*counter)++;
}

/* auto_block manbani blocklist'ga qo'shadi.
 *
 * Chelak orqali o'tgan har bir paket uchun emas, faqat chegara
 * kesib o'tilganda chaqiriladi: map yozish tez yo'ldagi eng qimmat
 * amallardan biri.
 */
static __always_inline void auto_block(const struct in6_addr *src,
                                       const struct cc01_config *cfg,
                                       __u64 now)
{
    struct cc01_block entry = {
        .expires_ns = cfg->auto_block_ns ? now + cfg->auto_block_ns : 0,
        .hits = 0,
    };

    /* BPF_NOEXIST: mavjud yozuvni bosib o'tmaymiz — unda operator
     * qo'lda qo'ygan muddat bo'lishi mumkin.
     */
    if (bpf_map_update_elem(&cc01_blocklist, src, &entry, BPF_NOEXIST) == 0)
        stat_inc(CC01_STAT_AUTO_BLOCKED);
}

/* rate_limit_ok token chelagini yangilaydi va paket o'tishi
 * mumkinligini aytadi.
 *
 * Chelak manba /64 bo'yicha: IPv6'da bitta xost odatda butun /64 ni
 * oladi, ya'ni manzil bo'yicha cheklash hujumchiga cheklovni bir
 * necha milliard manzil bilan chetlab o'tish imkonini berardi.
 */
static __always_inline int rate_limit_ok(const struct in6_addr *src,
                                         const struct cc01_config *cfg,
                                         __u64 now)
{
    if (cfg->rate_pps == 0)
        return 1;   /* cheklov o'chirilgan */

    struct cc01_rl_key key = {};
    __builtin_memcpy(key.prefix, src, sizeof(key.prefix));

    struct cc01_rl_value *bucket = bpf_map_lookup_elem(&cc01_ratelimit, &key);
    if (!bucket) {
        /* Yangi manba — chelak to'la boshlanadi. Bo'sh boshlansa
         * har bir yangi ulanish birinchi paketidayoq tashlanardi.
         */
        struct cc01_rl_value fresh = {
            .tokens_milli = (__u64)cfg->burst * 1000,
            .last_ns = now,
            .dropped = 0,
        };

        /* Map to'lgan bo'lsa yozib bo'lmaydi. Bunda paketni
         * O'TKAZAMIZ (fail-open) va buni alohida hisoblaymiz.
         *
         * Fail-closed xavfliroq bo'lardi: soxta manbalar bilan map
         * to'ldirilsa, hamma yangi manba tashlanardi — ya'ni
         * hujumchi butun xizmatni o'chirib qo'yardi. Hisoblagich
         * esa operatorga map to'lganini ko'rsatadi.
         */
        if (bpf_map_update_elem(&cc01_ratelimit, &key, &fresh, BPF_ANY) != 0)
            stat_inc(CC01_STAT_RL_MAP_FULL);

        return 1;
    }

    int allowed;
    __u64 dropped;

    bpf_spin_lock(&bucket->lock);

    /* To'ldirish: o'tgan vaqtga mutanosib.
     *
     * Vaqt orqaga ketishi mumkin emas (monotonik soat), lekin
     * ehtiyot uchun tekshiramiz — ayirma manfiy bo'lsa u ulkan
     * musbat songa aylanardi va chelak cheksiz to'lardi.
     */
    __u64 elapsed = now > bucket->last_ns ? now - bucket->last_ns : 0;
    bucket->last_ns = now;

    /* elapsed (ns) * pps / 1e6 = millitokenlar. */
    __u64 refill = (elapsed / 1000000) * cfg->rate_pps;
    __u64 ceiling = (__u64)cfg->burst * 1000;

    bucket->tokens_milli += refill;
    if (bucket->tokens_milli > ceiling)
        bucket->tokens_milli = ceiling;

    if (bucket->tokens_milli >= 1000) {
        bucket->tokens_milli -= 1000;
        allowed = 1;
    } else {
        bucket->dropped++;
        allowed = 0;
    }
    dropped = bucket->dropped;

    bpf_spin_unlock(&bucket->lock);

    if (!allowed && cfg->auto_block_after != 0 && dropped == cfg->auto_block_after)
        auto_block(src, cfg, now);

    return allowed;
}

/* emit_xdp_event tashlangan paket haqida hodisa yuboradi.
 *
 * Namuna olish tc dagidek: hujum paytida har bir tashlash uchun
 * hodisa yuborish kuzatuv vositasini xizmatni o'chirish vositasiga
 * aylantirardi.
 */
static __always_inline void emit_xdp_event(const struct in6_addr *src,
                                           __u8 stage, __u8 dry_run,
                                           const struct cc01_config *cfg,
                                           __u32 drop_counter)
{
    __u32 sample = cfg->event_sample;
    if (sample == 0)
        return;

    if (sample > 1) {
        __u64 *counter = bpf_map_lookup_elem(&cc01_stats, &drop_counter);
        if (counter && (*counter % sample) != 0)
            return;
    }

    struct cc01_xdp_event *event =
        bpf_ringbuf_reserve(&cc01_xdp_events, sizeof(*event), 0);
    if (!event) {
        stat_inc(CC01_STAT_EVENT_LOST);
        return;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(event->src, src, sizeof(event->src));
    event->stage = stage;
    event->dry_run = dry_run;
    __builtin_memset(event->_pad, 0, sizeof(event->_pad));

    bpf_ringbuf_submit(event, 0);
}

/* is_amplification_port — kuchaytirilgan hujumlarda ishlatiladigan
 * manba portlari (DEV_SPEC §4.3).
 *
 * Bu portlardan kelgan paket soxta manzil bilan yuborilgan so'rovga
 * JAVOB bo'lishi mumkin: hujumchi bizning manzilimizni ko'rsatib
 * so'ragan va javob bizga kelyapti.
 */
static __always_inline int is_amplification_port(__u16 port)
{
    return port == 53      /* DNS */
        || port == 123     /* NTP */
        || port == 1900    /* SSDP */
        || port == 11211;  /* memcached */
}

SEC("xdp")
int cc01_xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    stat_inc(CC01_STAT_TOTAL);

    /* ── Bosqich 0: sanity ────────────────────────────────── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) {
        stat_inc(CC01_STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    /* IPv6 bo'lmagan trafik bizga tegishli emas — tegmaymiz.
     *
     * Bu interfeysda boshqa xizmatlar ham ishlashi mumkin va ularni
     * kesib qo'yish filtrning vazifasi emas.
     */
    if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
        stat_inc(CC01_STAT_NOT_IPV6);
        return XDP_PASS;
    }

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > end) {
        stat_inc(CC01_STAT_DROP_MALFORMED);
        return XDP_DROP;
    }

    /* Konfiguratsiya yo'q bo'lsa FAIL-OPEN (DEV_SPEC §4.4).
     *
     * Sabab: config map bo'sh bo'lishi userspace hali yozib
     * ulgurmaganini bildiradi. Bunda hamma paketni tashlash butun
     * tarmoqni o'ldirardi — va buni sezish qiyin bo'lardi.
     */
    __u32 zero = 0;
    struct cc01_config *cfg = bpf_map_lookup_elem(&cc01_config_map, &zero);
    if (!cfg) {
        stat_inc(CC01_STAT_PASS);
        return XDP_PASS;
    }

    __u8 dry_run = (cfg->flags & CC01_F_ENFORCE) ? 0 : 1;

    /* ── Bosqich 1: blocklist ─────────────────────────────── */
    struct cc01_block *blocked = bpf_map_lookup_elem(&cc01_blocklist, &ip6->saddr);
    if (blocked) {
        __u64 now = bpf_ktime_get_ns();

        if (blocked->expires_ns == 0 || blocked->expires_ns > now) {
            /* Hisoblagich ATOMIK oshiriladi: bu yozuv hamma yadro
             * uchun umumiy, per-CPU emas.
             */
            __sync_fetch_and_add(&blocked->hits, 1);
            stat_inc(CC01_STAT_DROP_BLOCKLIST);
            emit_xdp_event(&ip6->saddr, CC01_STAGE_BLOCKLIST, dry_run, cfg,
                           CC01_STAT_DROP_BLOCKLIST);

            /* Dry-run: hisoblaymiz, lekin tashlamaymiz. */
            if (dry_run) {
                stat_inc(CC01_STAT_PASS);
                return XDP_PASS;
            }
            return XDP_DROP;
        }
    }

    /* ── Bosqich 2: tezlik cheklovi ───────────────────────── */
    if (!rate_limit_ok(&ip6->saddr, cfg, bpf_ktime_get_ns())) {
        stat_inc(CC01_STAT_DROP_RATELIMIT);
        emit_xdp_event(&ip6->saddr, CC01_STAGE_RATELIMIT, dry_run, cfg,
                       CC01_STAT_DROP_RATELIMIT);

        /* Dry-run: hisoblaymiz, lekin tashlamaymiz. */
        if (dry_run) {
            stat_inc(CC01_STAT_PASS);
            return XDP_PASS;
        }
        return XDP_DROP;
    }

    /* ── Bosqich 3: UDP ko'rish ───────────────────────────── */
    if (ip6->nexthdr == IPPROTO_UDP) {
        struct udphdr { __u16 source, dest, len, check; } *udp = (void *)(ip6 + 1);
        if ((void *)(udp + 1) > end) {
            stat_inc(CC01_STAT_DROP_MALFORMED);
            return XDP_DROP;
        }

        __u16 sport = bpf_ntohs(udp->source);
        __u16 dport = bpf_ntohs(udp->dest);

        /* Kuchaytirilgan hujum: bu portlardan kelgan paket soxta
         * manzil bilan yuborilgan so'rovga javob bo'lishi mumkin.
         */
        if ((cfg->flags & CC01_F_DROP_AMPLIFY) && is_amplification_port(sport)) {
            stat_inc(CC01_STAT_DROP_AMPLIFY);
            emit_xdp_event(&ip6->saddr, CC01_STAGE_AMPLIFY, dry_run, cfg,
                           CC01_STAT_DROP_AMPLIFY);

            if (dry_run) {
                stat_inc(CC01_STAT_PASS);
                return XDP_PASS;
            }
            return XDP_DROP;
        }

        /* ── Bosqich 4: cc01 datapath'i ───────────────────── */
        if (cfg->overlay_port != 0 && dport == cfg->overlay_port) {
            stat_inc(CC01_STAT_REDIRECT);

            /* AF_XDP soketi ulanmagan bo'lsa fallback XDP_PASS:
             * paket odatdagi yadro steki orqali cc01d ning UDP
             * soketiga boradi. Shu sababdan bu yo'lni yoqish
             * xavfsiz.
             */
            return bpf_redirect_map(&cc01_xsks, ctx->rx_queue_index, XDP_PASS);
        }
    }

    stat_inc(CC01_STAT_PASS);
    return XDP_PASS;
}
