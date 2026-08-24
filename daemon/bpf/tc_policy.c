// SPDX-License-Identifier: GPL-2.0
/* cc01 zero-trust policy filtri (DEV_SPEC §4.1, tc_ingress).
 *
 * # Nega tc, XDP emas
 *
 * Zero-trust ACL ICHKI overlay manzillari bo'yicha yoziladi: "node A
 * node B ning 443-portiga kira oladi". XDP `eth0` da SHIFRLANGAN
 * tashqi paketni ko'radi va uning ichi unga ko'rinmaydi.
 *
 * `cc0` ga kirayotgan paket esa allaqachon ochilgan — cc01d uni
 * deshifrlab TUN'ga yozgan. Aynan shu nuqtada ichki manzillar
 * ko'rinadi.
 *
 * Hujjatning §4.3 dagi psevdokodi policy'ni XDP ichiga qo'yadi va
 * §4.1 dagi jadval tc_ingress ga — ular zid. To'g'risi tc.
 *
 * # L2 sarlavhasi YO'Q
 *
 * `cc0` — TUN (TAP emas), ya'ni nuqta-nuqta L3 qurilmasi va
 * paketlarda Ethernet sarlavhasi bo'lmaydi. Dastur shuni SHART deb
 * qabul qiladi; userspace biriktirishda interfeysda MAC yo'qligini
 * tekshiradi.
 *
 * Buni avtomatik aniqlashga urinish xato bo'lardi: Ethernet
 * freymining birinchi bayti MAC manzilining bayti va uning yuqori
 * yarmi 6 bo'lishi mumkin — ya'ni "IPv6 versiyasi 6 mi" tekshiruvi
 * ishonchsiz.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "cc01_maps.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, CC01_PSTAT__MAX);
} cc01_policy_stats SEC(".maps");

/* Sozlama. XDP dagidan ALOHIDA tuzilma va alohida map: ikki dastur
 * mustaqil biriktiriladi va mustaqil rivojlanadi.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct cc01_policy_cfg);
    __uint(max_entries, 1);
} cc01_policy_config SEC(".maps");

/* 1-bosqich: manba prefiksi → identity. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct cc01_identity_key);
    __type(value, __u32);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cc01_identity SEC(".maps");

/* 2-bosqich: (identity, port, protokol) → hukm. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct cc01_policy_key);
    __type(value, struct cc01_policy_value);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cc01_policy SEC(".maps");

/* Hodisalar halqasi.
 *
 * 256 KB: bir necha ming hodisani ushlaydi va userspace ularni
 * o'qib ulguradi. Kattaroq bufer xotira sarflaydi va hech narsa
 * qo'shmaydi — hodisalar to'planib qolsa, muammo o'qish tezligida,
 * bufer o'lchamida emas.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cc01_events SEC(".maps");

/* Hukm keshi.
 *
 * LRU_HASH: yozuvlar avtomatik siqib chiqariladi va bu yerda
 * bpf_spin_lock kerak emas — hisoblagichlar atomik qo'shish bilan
 * yangilanadi, `last_seen_ns` esa oddiy yozuv (oxirgi yozuvchi
 * yutadi va bu zararsiz).
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct cc01_ct_key);
    __type(value, struct cc01_ct_value);
    __uint(max_entries, 262144);
} cc01_conntrack SEC(".maps");

static __always_inline void pstat_inc(__u32 index)
{
    __u64 *counter = bpf_map_lookup_elem(&cc01_policy_stats, &index);
    if (counter)
        (*counter)++;
}

/* l4_ports IPv6 paketidan port ma'lumotini oladi.
 *
 * Extension header'lar bo'ylab yurilmaydi: cc01 overlay'ida ular
 * ishlatilmaydi va ular bo'ylab yurish verifier byudjetini yeb
 * qo'yadi. Noma'lum next-header'da portlar nol qoladi va faqat
 * "istalgan port" qoidalari mos keladi.
 */
static __always_inline void l4_ports(const struct ipv6hdr *ip6, void *end,
                                     __u8 *proto, __u16 *sport, __u16 *dport)
{
    *proto = ip6->nexthdr;
    *sport = 0;
    *dport = 0;

    /* TCP va UDP sarlavhalarining birinchi to'rt bayti bir xil:
     * manba porti, keyin maqsad porti. Ikkalasi uchun bitta o'qish
     * yetarli.
     */
    if (*proto == IPPROTO_TCP || *proto == IPPROTO_UDP) {
        struct l4hdr { __u16 source, dest; } *l4 = (void *)(ip6 + 1);
        if ((void *)(l4 + 1) <= end) {
            *sport = bpf_ntohs(l4->source);
            *dport = bpf_ntohs(l4->dest);
        }
    }
}

/* lookup_verdict uch bosqichda qoida qidiradi — aniqroqdan
 * umumiyroqqa.
 *
 * Halqa emas, ochib yozilgan: verifier halqalarni qiyin hazm qiladi
 * va uchta qidiruv shundoq ham ko'rinib turibdi.
 */
static __always_inline struct cc01_policy_value *
lookup_verdict(__u32 identity, __u16 dport, __u8 proto, __u8 direction)
{
    struct cc01_policy_key key = {
        .identity = identity,
        .dport = dport,
        .proto = proto,
        .direction = direction,
    };

    /* 1. Aniq port va protokol. */
    struct cc01_policy_value *rule = bpf_map_lookup_elem(&cc01_policy, &key);
    if (rule)
        return rule;

    /* 2. Istalgan port, shu protokol — masalan "hamma ICMPv6". */
    key.dport = 0;
    rule = bpf_map_lookup_elem(&cc01_policy, &key);
    if (rule)
        return rule;

    /* 3. Istalgan port va protokol — shu manbaga to'liq ruxsat. */
    key.proto = 0;
    return bpf_map_lookup_elem(&cc01_policy, &key);
}

/* pstat_read hisoblagich qiymatini qaytaradi (namuna olish uchun). */
static __always_inline __u64 pstat_read(__u32 index)
{
    __u64 *counter = bpf_map_lookup_elem(&cc01_policy_stats, &index);
    return counter ? *counter : 0;
}

/* emit_event tashlangan paket haqida hodisa yuboradi.
 *
 * # Namuna olish
 *
 * Deny-by-default siyosatida qoidalar to'liq yozilmagan bo'lsa
 * HAMMA paket tashlanadi. Har biri uchun hodisa yuborish ring
 * bufferni to'ldirib, CPU ni yeb qo'yardi — ya'ni kuzatuv vositasi
 * xizmatni o'chirish vositasiga aylanardi.
 *
 * Shuning uchun har `sample` tashlashdan bittasi yuboriladi.
 * Hisoblagich sifatida PER-CPU drop hisoblagichi ishlatiladi:
 * alohida map kerak emas va u shundoq ham oshirilgan.
 */
static __always_inline void emit_event(const struct ipv6hdr *ip6,
                                       __u16 dport, __u8 proto,
                                       __u32 identity, __u32 rule_id,
                                       __u8 dry_run,
                                       const struct cc01_policy_cfg *cfg)
{
    __u32 sample = cfg->event_sample;
    if (sample == 0)
        return;   /* hodisalar o'chirilgan */

    if (sample > 1 && (pstat_read(CC01_PSTAT_DROP) % sample) != 0)
        return;

    struct cc01_event *event = bpf_ringbuf_reserve(&cc01_events, sizeof(*event), 0);
    if (!event) {
        /* Bufer to'lgan. Hodisa yo'qoladi, lekin FILTRLASH
         * TO'XTAMAYDI — kuzatuv hech qachon himoyadan muhimroq
         * emas (DEV_SPEC §4.5).
         */
        pstat_inc(CC01_PSTAT_EVENT_LOST);
        return;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(event->src, &ip6->saddr, sizeof(event->src));
    __builtin_memcpy(event->dst, &ip6->daddr, sizeof(event->dst));
    event->dport = dport;
    event->proto = proto;
    event->verdict = CC01_VERDICT_DROP;
    event->identity = identity;
    event->rule_id = rule_id;
    event->dry_run = dry_run;
    event->_pad[0] = 0;
    event->_pad[1] = 0;
    event->_pad[2] = 0;

    bpf_ringbuf_submit(event, 0);
}

/* ct_build kesh kalitini yig'adi. */
static __always_inline void ct_build(struct cc01_ct_key *key,
                                     const struct ipv6hdr *ip6,
                                     __u16 sport, __u16 dport, __u8 proto,
                                     __u8 direction)
{
    __builtin_memset(key, 0, sizeof(*key));
    __builtin_memcpy(key->src, &ip6->saddr, sizeof(key->src));
    __builtin_memcpy(key->dst, &ip6->daddr, sizeof(key->dst));
    key->sport = sport;
    key->dport = dport;
    key->proto = proto;
    key->direction = direction;
}

/* clamp_mss chiquvchi TCP SYN paketidagi MSS opsiyasini
 * kichraytiradi.
 *
 * # Nega kerak
 *
 * Overlay MTU 1280, uchlar esa yo'lni 1500 deb hisoblab kattaroq
 * MSS kelishib oladi. Natijada segmentlar sig'maydi va PMTU aniqlash
 * ICMPv6 "Packet Too Big" ga tayanadi — u esa ko'pincha filtrlangan.
 * Oqibat: ulanish o'rnatiladi, lekin katta uzatmalar QOTIB QOLADI.
 *
 * # Nega faqat SYN
 *
 * MSS faqat ulanish o'rnatilayotganda kelishiladi. Boshqa
 * paketlarda MSS opsiyasi umuman bo'lmaydi.
 */
static __always_inline void clamp_mss(struct __sk_buff *skb, __u16 limit)
{
    if (limit == 0)
        return;

    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    struct ipv6hdr *ip6 = data;
    if ((void *)(ip6 + 1) > end || ip6->nexthdr != IPPROTO_TCP)
        return;

    struct tcphdr *tcp = (void *)(ip6 + 1);
    if ((void *)(tcp + 1) > end || !tcp->syn)
        return;

    /* Opsiyalar sarlavhadan keyin boshlanadi. doff — 32-bitlik
     * so'zlarda; 5 dan katta bo'lsa opsiyalar bor.
     */
    __u32 doff = tcp->doff * 4;
    if (doff <= sizeof(*tcp) || doff > 60)
        return;

    __u32 tcp_off = (__u32)((void *)tcp - data);
    __u32 opt_off = tcp_off + sizeof(*tcp);
    __u32 opt_end = tcp_off + doff;

    /* Opsiyalar bo'ylab yuramiz. Halqa CHEKLANGAN: TCP opsiyalari
     * eng ko'pi 40 bayt va eng kichigi 1 bayt, ya'ni 20 ta qadam
     * har qanday holatni qoplaydi. Verifier cheksiz halqani rad
     * etadi.
     */
    #pragma unroll
    for (int step = 0; step < 20; step++) {
        if (opt_off + 1 > opt_end)
            return;

        __u8 kind;
        if (bpf_skb_load_bytes(skb, opt_off, &kind, 1) < 0)
            return;

        if (kind == 0)   /* End of options */
            return;
        if (kind == 1) { /* NOP */
            opt_off += 1;
            continue;
        }

        if (opt_off + 2 > opt_end)
            return;

        __u8 len;
        if (bpf_skb_load_bytes(skb, opt_off + 1, &len, 1) < 0)
            return;
        if (len < 2 || opt_off + len > opt_end)
            return;

        if (kind == 2 && len == 4) {
            __u16 mss;
            if (bpf_skb_load_bytes(skb, opt_off + 2, &mss, 2) < 0)
                return;

            __u16 current = bpf_ntohs(mss);
            if (current <= limit)
                return;   /* allaqachon yetarlicha kichik */

            __u16 replacement = bpf_htons(limit);

            /* Checksum AVVAL tuzatiladi: bpf_skb_store_bytes
             * data/data_end ni yaroqsiz qiladi va undan keyin
             * paketga murojaat qilib bo'lmaydi.
             */
            __u32 csum_off = tcp_off + offsetof(struct tcphdr, check);
            if (bpf_l4_csum_replace(skb, csum_off, mss, replacement, 2) < 0)
                return;
            if (bpf_skb_store_bytes(skb, opt_off + 2, &replacement, 2, 0) < 0)
                return;

            pstat_inc(CC01_PSTAT_MSS_CLAMPED);
            return;
        }

        opt_off += len;
    }
}

/* set_dscp chiquvchi paketga DSCP qo'yadi.
 *
 * IPv6'da traffic class sarlavhaning birinchi ikki baytiga
 * taqsimlangan: version(4) | tc(8) | flowlabel(20). IPv6'da
 * sarlavha checksum'i YO'Q, ya'ni faqat baytlarni yozish yetarli.
 */
static __always_inline void set_dscp(struct __sk_buff *skb, __u8 dscp)
{
    if (dscp == 0)
        return;

    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    if (data + 2 > end)
        return;

    __u8 head[2];
    if (bpf_skb_load_bytes(skb, 0, head, 2) < 0)
        return;

    /* tc = DSCP(6 bit) | ECN(2 bit). ECN ga TEGMAYMIZ — u
     * tiqilinlik nazorati uchun va uni o'chirish TCP ni
     * sekinlashtirardi.
     */
    __u8 ecn = head[1] >> 4 & 0x3;
    head[0] = (head[0] & 0xf0) | (dscp >> 2);
    head[1] = (head[1] & 0x0f) | ((dscp & 0x3) << 6) | (ecn << 4);

    (void)bpf_skb_store_bytes(skb, 0, head, 2, 0);
}

/* evaluate — ikkala yo'nalish uchun umumiy mantiq.
 *
 * Yagona farq qaysi manzil bo'yicha identity qidirilishida:
 *
 *	kirish   MANBA prefiksi — "kim bizga murojaat qilyapti"
 *	chiqish  MAQSAD prefiksi — "biz kimga murojaat qilyapmiz"
 */
static __always_inline int evaluate(struct __sk_buff *skb, __u8 direction)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    pstat_inc(direction == CC01_DIR_EGRESS
                  ? CC01_PSTAT_EGRESS_TOTAL
                  : CC01_PSTAT_TOTAL);

    if (skb->protocol != bpf_htons(ETH_P_IPV6)) {
        pstat_inc(CC01_PSTAT_NOT_IPV6);
        return TC_ACT_OK;
    }

    /* L3 qurilma: paket to'g'ridan-to'g'ri IPv6 sarlavhasidan
     * boshlanadi.
     */
    struct ipv6hdr *ip6 = data;
    if ((void *)(ip6 + 1) > end) {
        pstat_inc(CC01_PSTAT_DROP_MALFORMED);
        return TC_ACT_SHOT;
    }

    __u32 zero = 0;
    struct cc01_policy_cfg *cfg = bpf_map_lookup_elem(&cc01_policy_config, &zero);
    if (!cfg) {
        /* Sozlama yo'q — fail-open (DEV_SPEC §4.4). Userspace hali
         * yozib ulgurmagan bo'lishi mumkin va bunda butun overlay'ni
         * kesib qo'yish eng yomon natija bo'lardi.
         */
        pstat_inc(CC01_PSTAT_ALLOW);
        return TC_ACT_OK;
    }

    __u8 proto;
    __u16 sport, dport;
    l4_ports(ip6, end, &proto, &sport, &dport);

    /* ── Tez yo'l: hukm keshi ─────────────────────────────── */
    struct cc01_ct_key ckey;
    ct_build(&ckey, ip6, sport, dport, proto, direction);

    struct cc01_ct_value *cached = bpf_map_lookup_elem(&cc01_conntrack, &ckey);

    /* Avlod mos kelmasa yozuv ESKIRGAN: qoidalar o'zgargan va
     * keshlangan hukm endi noto'g'ri bo'lishi mumkin.
     */
    if (cached && cached->policy_gen == cfg->policy_gen) {
        cached->last_seen_ns = bpf_ktime_get_ns();
        __sync_fetch_and_add(&cached->packets, 1);
        pstat_inc(CC01_PSTAT_CT_HIT);

        if (cached->verdict == CC01_VERDICT_ALLOW) {
            pstat_inc(CC01_PSTAT_ALLOW);
            if (direction == CC01_DIR_EGRESS) {
                clamp_mss(skb, cfg->mss_clamp);
                set_dscp(skb, cfg->dscp);
            }
            return TC_ACT_OK;
        }

        pstat_inc(CC01_PSTAT_DROP);
        if (direction == CC01_DIR_EGRESS)
            pstat_inc(CC01_PSTAT_EGRESS_DROP);
        if (!(cfg->flags & CC01_F_ENFORCE))
            return TC_ACT_OK;
        return TC_ACT_SHOT;
    }

    pstat_inc(CC01_PSTAT_CT_MISS);

    /* ── Sekin yo'l: to'liq policy qidiruvi ───────────────── */

    /* 1-bosqich: identity. Kirishda manba, chiqishda maqsad. */
    struct cc01_identity_key ikey = {.prefixlen = 128};
    if (direction == CC01_DIR_EGRESS)
        __builtin_memcpy(ikey.addr, &ip6->daddr, sizeof(ikey.addr));
    else
        __builtin_memcpy(ikey.addr, &ip6->saddr, sizeof(ikey.addr));

    __u32 identity = CC01_IDENTITY_UNKNOWN;
    __u32 *found = bpf_map_lookup_elem(&cc01_identity, &ikey);
    if (found)
        identity = *found;

    /* 2-bosqich: hukm. */
    struct cc01_policy_value *rule = lookup_verdict(identity, dport, proto, direction);

    __u8 verdict = CC01_VERDICT_DROP;   /* deny-by-default */
    __u32 rule_id = 0;

    if (rule) {
        verdict = rule->verdict;
        rule_id = rule->rule_id;
        __sync_fetch_and_add(&rule->hits, 1);
    } else {
        pstat_inc(CC01_PSTAT_NO_RULE);
    }

    /* Hukmni keshlaymiz — keyingi paketlar bitta qidiruv bilan
     * cheklanadi.
     *
     * Taqiqlar ham keshlanadi: hujum paytida ular eng ko'p
     * uchraydigan holat va ularni har safar qayta hisoblash eng
     * qimmat yo'l bo'lardi. LRU yozuvlarni o'zi siqib chiqaradi.
     */
    struct cc01_ct_value entry = {
        .last_seen_ns = bpf_ktime_get_ns(),
        .packets = 1,
        .rule_id = rule_id,
        .policy_gen = cfg->policy_gen,
        .verdict = verdict,
    };
    bpf_map_update_elem(&cc01_conntrack, &ckey, &entry, BPF_ANY);

    if (verdict == CC01_VERDICT_ALLOW) {
        pstat_inc(CC01_PSTAT_ALLOW);
        if (direction == CC01_DIR_EGRESS) {
            clamp_mss(skb, cfg->mss_clamp);
            set_dscp(skb, cfg->dscp);
        }
        return TC_ACT_OK;
    }

    pstat_inc(CC01_PSTAT_DROP);
    if (direction == CC01_DIR_EGRESS)
        pstat_inc(CC01_PSTAT_EGRESS_DROP);

    /* Dry-run: hisoblaymiz, lekin o'tkazamiz.
     *
     * Deny-by-default siyosatida bu ayniqsa muhim: qoidalar to'liq
     * yozilmagan bo'lsa, enforce rejimi butun trafikni kesib
     * qo'yardi.
     */
    __u8 dry_run = (cfg->flags & CC01_F_ENFORCE) ? 0 : 1;

    emit_event(ip6, dport, proto, identity, rule_id, dry_run, cfg);

    if (dry_run) {
        if (direction == CC01_DIR_EGRESS) {
            clamp_mss(skb, cfg->mss_clamp);
            set_dscp(skb, cfg->dscp);
        }
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}

SEC("tc")
int cc01_tc_ingress(struct __sk_buff *skb)
{
    return evaluate(skb, CC01_DIR_INGRESS);
}

SEC("tc")
int cc01_tc_egress(struct __sk_buff *skb)
{
    return evaluate(skb, CC01_DIR_EGRESS);
}
