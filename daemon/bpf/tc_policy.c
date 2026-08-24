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

/* Sozlama: XDP dagi bilan bir xil tuzilma, alohida nusxa.
 *
 * Ikkala dastur bir xil map'ni ULASHMAYDI: ular alohida
 * biriktiriladi va biri o'chirilganda ikkinchisi ishlashda davom
 * etishi kerak.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct cc01_config);
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
                                     __u8 *proto, __u16 *dport)
{
    *proto = ip6->nexthdr;
    *dport = 0;

    if (*proto == IPPROTO_TCP) {
        struct tcphdr { __u16 source, dest; } *tcp = (void *)(ip6 + 1);
        if ((void *)(tcp + 1) <= end)
            *dport = bpf_ntohs(tcp->dest);
        return;
    }

    if (*proto == IPPROTO_UDP) {
        struct udphdr { __u16 source, dest; } *udp = (void *)(ip6 + 1);
        if ((void *)(udp + 1) <= end)
            *dport = bpf_ntohs(udp->dest);
    }
}

/* lookup_verdict uch bosqichda qoida qidiradi — aniqroqdan
 * umumiyroqqa.
 *
 * Halqa emas, ochib yozilgan: verifier halqalarni qiyin hazm qiladi
 * va uchta qidiruv shundoq ham ko'rinib turibdi.
 */
static __always_inline struct cc01_policy_value *
lookup_verdict(__u32 identity, __u16 dport, __u8 proto)
{
    struct cc01_policy_key key = {
        .identity = identity,
        .dport = dport,
        .proto = proto,
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

SEC("tc")
int cc01_tc_policy(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;

    pstat_inc(CC01_PSTAT_TOTAL);

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
    struct cc01_config *cfg = bpf_map_lookup_elem(&cc01_policy_config, &zero);
    if (!cfg) {
        /* Sozlama yo'q — fail-open (DEV_SPEC §4.4). Userspace hali
         * yozib ulgurmagan bo'lishi mumkin va bunda butun overlay'ni
         * kesib qo'yish eng yomon natija bo'lardi.
         */
        pstat_inc(CC01_PSTAT_ALLOW);
        return TC_ACT_OK;
    }

    /* 1-bosqich: manba prefiksidan identity. */
    struct cc01_identity_key ikey = {.prefixlen = 128};
    __builtin_memcpy(ikey.addr, &ip6->saddr, sizeof(ikey.addr));

    __u32 identity = CC01_IDENTITY_UNKNOWN;
    __u32 *found = bpf_map_lookup_elem(&cc01_identity, &ikey);
    if (found)
        identity = *found;

    /* 2-bosqich: hukm. */
    __u8 proto;
    __u16 dport;
    l4_ports(ip6, end, &proto, &dport);

    struct cc01_policy_value *rule = lookup_verdict(identity, dport, proto);

    __u8 verdict = CC01_VERDICT_DROP;   /* deny-by-default */
    if (rule) {
        verdict = rule->verdict;
        __sync_fetch_and_add(&rule->hits, 1);
    } else {
        pstat_inc(CC01_PSTAT_NO_RULE);
    }

    if (verdict == CC01_VERDICT_ALLOW) {
        pstat_inc(CC01_PSTAT_ALLOW);
        return TC_ACT_OK;
    }

    pstat_inc(CC01_PSTAT_DROP);

    /* Dry-run: hisoblaymiz, lekin o'tkazamiz.
     *
     * Deny-by-default siyosatida bu ayniqsa muhim: qoidalar to'liq
     * yozilmagan bo'lsa, enforce rejimi butun trafikni kesib
     * qo'yardi.
     */
    if (!(cfg->flags & CC01_F_ENFORCE))
        return TC_ACT_OK;

    return TC_ACT_SHOT;
}
