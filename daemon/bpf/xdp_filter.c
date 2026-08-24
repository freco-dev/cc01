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

static __always_inline void stat_inc(__u32 index)
{
    __u64 *counter = bpf_map_lookup_elem(&cc01_stats, &index);
    if (counter)
        (*counter)++;
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

            /* Dry-run: hisoblaymiz, lekin tashlamaymiz. */
            if (!(cfg->flags & CC01_F_ENFORCE)) {
                stat_inc(CC01_STAT_PASS);
                return XDP_PASS;
            }
            return XDP_DROP;
        }
    }

    stat_inc(CC01_STAT_PASS);
    return XDP_PASS;
}
