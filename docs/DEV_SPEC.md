# cc01 — Texnik Topshiriq va Amalga Oshirish Spetsifikatsiyasi (DEV_SPEC.md)

| Maydon | Qiymat |
| --- | --- |
| Hujjat versiyasi | `1.0.0` |
| Status | `Implementation Ready` (§1–§2, §6, §8) · `Design` (§3–§5 — hali yozilmagan) |
| Auditoriya | Backend (Go), Systems (Rust/C), SRE/DevOps, QA |
| Old shart | `ARCHITECTURE.md` o'qilgan bo'lishi shart (ayniqsa §1.6 va §3.4) |
| Kod repozitoriysi | `git@github.com:<org>/cc01.git` (monorepo) |

> **Hujjatni o'qish tartibi:** §1 stack → §2 repo → §3 klient protokoli → §4 eBPF → §5 tunneling/CLI → §6 access-server → §7 sifat → §8 roadmap → §9 DoD → §10 ochiq savollar.
>
> **Diqqat:** §3–§5 **maqsadli** holatni tasvirlaydi va hali yozilmagan. Repodagi hozirgi kod holati `ARCHITECTURE.md` §1.6 va quyidagi §2.0 da. Ish ketma-ketligi — §8 Faza 0.

---

## 1. Tech Stack & Dependencies

### 1.1 Til va komponentlar bo'yicha taqsimot

| Komponent | Til | Sabab |
| --- | --- | --- |
| `cc01d` (klient daemon) | **Go 1.23+** | Tez ishlab chiqish, kross-kompilyatsiya, goroutine I/O modeli |
| `cc01` (CLI) | **Go** | Daemon bilan bir xil protobuf, bitta binar |
| eBPF dasturlari | **C (clang -target bpf)** | BPF verifier uchun yagona to'liq qo'llab-quvvatlanadigan yo'l |
| eBPF loader/manager | **Go (`cilium/ebpf`)** | CO-RE, BTF, mapping'lar uchun sof Go — CGO kerak emas |
| Kritik crypto/datapath (v1.2+) | **Rust** | `cc01-fastpath` moduli: AF_XDP + crypto, zero-copy |
| Control Plane servislari | **Go 1.23 + gRPC** | Raft (`hashicorp/raft`), yuqori concurrency |
| Edge Ingress | **Go** (+ Rust `cc01-l4` v1.2'da) | QUIC (`quic-go`), TLS, HTTP/3 |
| `access-server` (Account Plane) | **C# / .NET 10** | Mavjud skelet; CRUD+billing domeni uchun EF Core va Identity ekotizimi (ADR-009) |
| Web Dashboard | **TypeScript + React** | Standart |
| Infra | **Terraform + Ansible + Kubernetes** | PoP provisioning; CP → k8s, DP → bare metal |

**Go vs .NET chegarasi (ADR-009):** hisob, tarif, billing va subdomain egaligi — `access-server`da (.NET). Node sertifikati, IPAM, NetworkMap, policy — Go CP'da. Chegara sinxron HTTP (mTLS) orqali, umumiy baza **yo'q** (ADR-010). Batafsil §6.

**Rust vs Go qarori (ADR-011):** MVP butunlay Go'da yoziladi (jamoa tezligi uchun). Profiling `crypto+TUN I/O` bottleneck ko'rsatsa, faqat `fastpath` moduli Rust'ga ko'chiriladi va `cgo`/UDS orqali ulanadi. Butun daemonni Rust'da yozish MVP muddatini ~2× uzaytiradi.

### 1.2 Bog'liqliklar (kutubxonalar)

**Klient (`cc01d`):**

| Paket | Versiya | Vazifa |
| --- | --- | --- |
| `github.com/cilium/ebpf` | `v0.16+` | eBPF yuklash, map boshqaruvi, CO-RE |
| `golang.zx2c4.com/wireguard/tun` | latest | TUN device abstraksiyasi (Linux/macOS/Windows) |
| `golang.zx2c4.com/wireguard/conn` | latest | Batch UDP (`sendmmsg`/`recvmmsg`), GSO/GRO |
| `github.com/flynn/noise` | `v1.1+` | Noise IK handshake |
| `golang.org/x/crypto` | latest | ChaCha20-Poly1305, Curve25519, BLAKE2s |
| `github.com/quic-go/quic-go` | `v0.48+` | Tunnel transport, HTTP/3 |
| `github.com/pion/stun/v2` | `v2.1+` | STUN klient |
| `github.com/pion/ice/v3` | `v3.0+` | ICE nomzod yig'ish (ixtiyoriy — o'z implementatsiyamiz ham bor) |
| `google.golang.org/grpc` | `v1.66+` | CP bilan aloqa + IPC |
| `github.com/vishvananda/netlink` | latest | Marshrut/manzil boshqaruvi (Linux) |
| `github.com/spf13/cobra` | `v1.8+` | CLI |
| `github.com/prometheus/client_golang` | latest | Metrikalar |
| `github.com/awnumar/memguard` | latest | Kalitlarni xotirada himoyalash |

**Control Plane:**

| Paket | Vazifa |
| --- | --- |
| `go.etcd.io/etcd/client/v3` yoki `hashicorp/raft` + `raft-boltdb` | Konsensus va KV |
| `github.com/libp2p/go-libp2p-kad-dht` | Decentralized fallback discovery |
| `github.com/spiffe/go-spiffe/v2` | SVID sertifikatlari |
| `github.com/redis/go-redis/v9` | Ephemeral endpoint cache |
| `github.com/caddyserver/certmagic` | ACME avtomatizatsiyasi |
| `github.com/ClickHouse/clickhouse-go/v2` | Audit/metrics sink |

**Access Server (`access-server`, NuGet):**

| Paket | Vazifa |
| --- | --- |
| `Microsoft.EntityFrameworkCore` + `Npgsql.EntityFrameworkCore.PostgreSQL` | ORM va PostgreSQL provayderi |
| `EFCore.NamingConventions` | snake_case — Postgres'da qo'shtirnoqsiz identifikatorlar |
| `Microsoft.EntityFrameworkCore.Design` | Migratsiya generatsiyasi (`Infrastructure` loyihasida) |
| `Microsoft.AspNetCore.Identity.EntityFrameworkCore` | Foydalanuvchi, parol hash, lockout |
| `Microsoft.AspNetCore.Authentication.Google` / `.OAuth` (GitHub) | OAuth provayderlari |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | Dashboard sessiyasi |
| `StackExchange.Redis` | Token lookup kesh, rate limit |
| `FluentValidation` | So'rov validatsiyasi |
| `Grpc.AspNetCore` + `Google.Protobuf` | Ichki kontrakt (Go bilan umumiy `proto/`) |
| `Serilog.AspNetCore` + `OpenTelemetry.Extensions.Hosting` | Log va telemetriya |
| `Microsoft.AspNetCore.OpenApi` | OpenAPI (allaqachon mavjud) |

### 1.3 Toolchain va minimal talablar

| Talab | Versiya | Izoh |
| --- | --- | --- |
| Go | ≥ 1.25 | gRPC `v1.83+` talabi (dastlab ≥1.23 rejalashtirilgan edi) |
| clang/LLVM | ≥ 17 | BPF target kompilyatsiyasi |
| Linux kernel (klient, to'liq funksiya) | ≥ 5.15 | BTF, `bpf_loop`, ring buffer |
| Linux kernel (edge, tavsiya) | ≥ 6.6 | XDP multi-buffer, `bpf_redirect_peer` |
| `bpftool` | ≥ 7.0 | Debug, map dump |
| Rust (fastpath) | ≥ 1.80 | `libbpf-rs`, `aya` alternativa |
| .NET SDK | ≥ 10.0 | `access-server` build va EF migratsiyalari |
| `dotnet-ef` | 10.0.11 | **Lokal tool** — `cd access-server && dotnet tool restore`. Global o'rnatilmaydi: versiya `access-server/dotnet-tools.json` da qayd etilgan |
| PostgreSQL | ≥ 16 | AP bazasi. Lokal: `make dev-up` → `127.0.0.1:15432` |
| Redis | ≥ 7 | Token kesh, rate limit. Lokal: `make dev-up` → `127.0.0.1:16379` |
| `buf` | ≥ 1.40 | Protobuf lint, generatsiya (Go + C#) |
| Docker/Podman | latest | Reproducible build |
| Kernel config | `CONFIG_BPF_SYSCALL=y`, `CONFIG_XDP_SOCKETS=y`, `CONFIG_DEBUG_INFO_BTF=y` | Preflight check `cc01 doctor` |

**Fallback matritsasi:** eBPF mavjud bo'lmasa (eski kernel, macOS, Windows) → `nftables`/`WFP` yoki sof userspace filtr; funksiya saqlanadi, unumdorlik pasayadi. `cc01 doctor` buni aniq xabar qiladi.

---

## 2. Project Structure (Monorepo)

**Qaror:** monorepo — chunki protobuf sxemalari, kripto kod va eBPF map struct'lari klient/CP/edge orasida umumiy. Polyrepo versiya nomuvofiqligini keltirib chiqaradi.

### 2.0 Hozirgi holat va ko'chirish xaritasi

Quyidagi §2.1 — **maqsadli** struktura. Repozitoriyda hozir uchta mustaqil modul yonma-yon turibdi, ularni bog'lovchi `go.work` ham, `proto/` ham yo'q:

```
cc01/
├── core-server/     Go modul — tunnel serveri (event :4321, public :80, TLS :443)
├── cli-client/      Go modul — minimal klient; `replace` orqali core-server'ga bog'langan
├── daemon/          Go modul — mesh datapath (Faza 1 da boshlandi)
├── control/         Go modul — Control Plane (Faza 1 da boshlandi)
├── access-server/   .NET solution — Account Plane
└── docs/            ARCHITECTURE.md · DEV_SPEC.md · adr/
```

**Oraliq struktura (Faza 0 oxirida yetiladigan holat).** To'liq `cmd/`+`internal/` ko'chirishni bir zarbada qilish ishni to'xtatib qo'yadi; shuning uchun avval umumiy kontrakt ajratiladi, modullar joyida qoladi:

```
cc01/
├── go.work                    # core-server + cli-client
├── Makefile                   # build · test · lint · proto · dotnet
├── proto/                     # ⭐ yagona kontrakt — ALOHIDA Go moduli
│   ├── go.mod                 #   github.com/freco-dev/cc01/proto
│   ├── cc01/v1/tunnel.proto   #   klient ↔ edge boshqaruv protokoli
│   ├── cc01/v1/access.proto   #   AP ↔ Edge ichki kontrakti
│   ├── cc01/v1/control.proto  #   node ↔ CP protokoli
│   ├── gen/                   #   generatsiya qilingan Go kodi (commit qilinadi)
│   └── buf.yaml · buf.gen.yaml
├── core-server/ · cli-client/ · daemon/ · control/ · access-server/
├── deploy/docker-compose.dev.yml   # postgres + redis + core + access
└── test/contract/             # AP ↔ Edge kontrakt testlari
```

**Ko'chirish xaritasi** — hozirgi har bir bo'lak maqsadli strukturada qayerga tushadi:

| Hozir | Maqsadli joy (§2.1) | Izoh |
| --- | --- | --- |
| `core-server/cc01.go` | `cmd/cc01-edge/` + `internal/edge/ingress/` | Tunnel registri va demux mantiqi ajratiladi |
| `core-server/server/` | `internal/edge/ingress/` | TCP/TLS listener abstraksiyasi |
| `core-server/tunnel/` | `internal/edge/mux/` | Keyinchalik QUIC stream mux bilan almashtiriladi |
| `core-server/events/` | `proto/cc01/v1/tunnel.proto` | ✅ `gob` → protobuf ko'chirildi (magic + versiya preambulasi bilan) |
| `core-server/config/` | `internal/pkg/config/` | Env → strukturalangan konfiguratsiya |
| `core-server/access/` | `internal/edge/access/` | AP ↔ Edge gRPC klienti, kesh va fail-static bilan |
| `core-server/utils.go` | `internal/edge/ingress/` (host parse) | Host header parse'i SNI router bilan almashtiriladi |
| `cli-client/` | `cmd/cc01/` | CLI qismi (§5.1) |
| `daemon/noise/` | `internal/daemon/noise/` | Mesh kripto qatlami: handshake, sessiya, replay oynasi |
| `daemon/tun/` | `internal/daemon/tun/` + `route/` | TUN qurilmasi, manzil va marshrut sozlash |
| `daemon/router/` | `internal/daemon/engine/` | Peer registri, allowed_ips LPM trie, cryptokey routing |
| `daemon/conn/` | `internal/daemon/conn/` | UDP transport, batch I/O |
| `daemon/engine/` | `internal/daemon/engine/` | Datapath: TUN ↔ router ↔ noise ↔ UDP |
| `daemon/cmd/cc01d/` | `cmd/cc01d/` | Daemon binari (hozircha statik peer konfiguratsiyasi) |
| `control/ipam/` | `internal/control/ipam/` | IPv6 taqsimlagich, ijara hayot sikli, Store abstraksiyasi |
| `control/registry/` | `internal/control/disco/` + `mapper/` | Node registri, NetworkMap, delta sync |
| `control/server/` | `internal/control/` | ControlService gRPC implementatsiyasi |
| `control/cmd/cc01-cp/` | `cmd/cc01-cp/` | Control Plane binari |
| `daemon/control/` | `internal/daemon/engine/` | CP klienti: NetworkMap → router peerlari |
| `daemon/stun/` | `internal/daemon/disco/` | STUN klienti (datapath soketi ustida) |
| `daemon/relay/` | `internal/edge/relaysvc/` (server) + `internal/daemon/relay/` (klient) | Relay: ko'r uzatuvchi |
| `daemon/path/` | `internal/daemon/disco/` | Yo'l holat mashinasi, disco ping/pong |
| `control/stunserver/` | `internal/control/signal/` | STUN binding serveri |
| `access-server/` | `access-server/` — **joyida qoladi** | .NET solution, Go workspace'dan tashqarida (ADR-009) |

**Qoida:** har bir ko'chirish alohida PR; funksionallik o'zgarishi va joy o'zgarishi bitta PR'da aralashtirilmaydi.

### 2.1 Maqsadli struktura

```
cc01/
├── go.work                        # Go workspace (multi-module)
├── Makefile                       # build, test, lint, bpf-gen, release
├── README.md · ARCHITECTURE.md · DEV_SPEC.md · SECURITY.md
│
├── proto/                         # ⭐ Yagona haqiqat manbai (source of truth)
│   ├── cc01/v1/control.proto      #   CP ↔ node protokoli
│   ├── cc01/v1/ipam.proto
│   ├── cc01/v1/signal.proto
│   ├── cc01/v1/policy.proto
│   ├── cc01/v1/tunnel.proto
│   ├── cc01/v1/daemon.proto       #   CLI ↔ daemon IPC
│   └── buf.yaml · buf.gen.yaml    #   buf lint + breaking change detection
│
├── cmd/                           # Barcha binarlar
│   ├── cc01/                      #   CLI (user-facing)
│   ├── cc01d/                     #   Klient daemon
│   ├── cc01-cp/                   #   Control Plane (all-in-one yoki bo'lingan)
│   ├── cc01-edge/                 #   Edge ingress + relay
│   └── cc01-ipamctl/              #   Operator utiliti
│
├── internal/
│   ├── daemon/                    # Klient yadrosi
│   │   ├── engine/                #   Asosiy holat mashinasi
│   │   ├── tun/                   #   TUN yaratish, batch I/O, platform-specific
│   │   │   ├── tun_linux.go · tun_darwin.go · tun_windows.go
│   │   ├── route/                 #   Marshrut jadvali sinxronizatsiyasi (netlink)
│   │   ├── conn/                  #   UDP socket, GSO/GRO, sendmmsg
│   │   ├── noise/                 #   Handshake, sessiya, rekey, replay window
│   │   ├── disco/                 #   ICE, STUN, hole punching, path probing
│   │   ├── relay/                 #   Relay klient (DERP-like)
│   │   ├── ipc/                   #   gRPC over UDS server
│   │   ├── tunnel/                #   ngrok-agent: local dial, QUIC stream mux
│   │   └── ebpfmgr/               #   eBPF load/attach/map sync
│   │
│   ├── bpf/                       # ⭐ eBPF C manbalari
│   │   ├── include/
│   │   │   ├── cc01_maps.h        #   Map ta'riflari (yagona manba)
│   │   │   ├── cc01_types.h       #   Struct'lar (Go tomonga generate qilinadi)
│   │   │   └── vmlinux.h          #   BTF-dan generate qilingan
│   │   ├── xdp_filter.c           #   Stage 0–5 pipeline
│   │   ├── tc_egress.c            #   Egress policy, MSS clamp, DSCP
│   │   ├── tc_ingress.c           #   Ingress policy, accounting
│   │   ├── sk_lookup.c            #   Port sharing (v1.2)
│   │   └── gen.go                 #   //go:generate bpf2go
│   │
│   ├── control/                   # CP servislari
│   │   ├── idp/ · disco/ · ipam/ · signal/ · policy/
│   │   ├── store/                 #   Raft abstraksiyasi
│   │   └── mapper/                #   NetworkMap qurish + delta hisoblash
│   │
│   ├── edge/
│   │   ├── ingress/               #   SNI router, HTTP/1.1-2-3
│   │   ├── tlsmgr/                #   ACME, sertifikat kesh
│   │   ├── mux/                   #   TCP port allocator, UDP session table
│   │   ├── relaysvc/              #   Relay server
│   │   └── bgp/                   #   BGP speaker integratsiyasi
│   │
│   └── pkg/                       # Umumiy kutubxonalar
│       ├── ipv6/                  #   Prefiks matematikasi, LPM trie
│       ├── crypto/ · logging/ · metrics/ · version/ · netmap/
│
├── fastpath/                      # Rust crate (v1.2+)
│   ├── Cargo.toml
│   └── src/{lib.rs, afxdp.rs, crypto.rs}
│
├── access-server/                 # ⭐ Account Plane — .NET solution (ADR-009)
│   ├── AccessServer.slnx
│   └── src/
│       ├── AccessServer.Domain/         #   Entity, User, ApiToken, Subdomain, Plan…
│       ├── AccessServer.Application/    #   Use-case'lar, validatsiya, DTO
│       ├── AccessServer.Infrastructure/ #   EF Core, Postgres, Redis, OAuth
│       └── AccessServer.Api/            #   Public REST + /internal gRPC listener
│
├── web/                           # React dashboard
├── deploy/
│   ├── terraform/{pop-tas1, pop-fra1, cp-cluster}
│   ├── ansible/roles/{edge, relay, bgp}
│   ├── k8s/{cp-*.yaml}
│   ├── packaging/                 #   nfpm → deb/rpm  ✅
│   └── systemd/cc01d.service      #   ✅
│
├── test/
│   ├── integration/               #   Docker Compose: 3 node + CP + relay
│   ├── netns/                     #   Linux netns bilan NAT simulyatsiyasi
│   ├── e2e/                       #   Real PoP'ga qarshi smoke testlar
│   └── fuzz/                      #   Paket parser fuzzing
│
└── docs/
    ├── adr/ADR-001..N.md
    ├── runbooks/
    └── api/
```

### 2.2 Modul chegaralari (import qoidalari)

```
cmd/*          → internal/*  ✅
internal/daemon → internal/pkg, internal/bpf  ✅
internal/daemon → internal/control            ❌ (faqat proto orqali)
internal/edge   → internal/daemon             ❌
internal/pkg    → hech nimaga bog'liq emas    ✅ (leaf)

access-server   → Go modullariga              ❌ (faqat proto/ orqali)
internal/edge   → access-server               ❌ (faqat HTTP/gRPC kontrakti)
proto/          → hech nimaga bog'liq emas    ✅ (ikkala tomon uchun leaf)
```

**AP chegarasi:** `access-server` va Go modullari **umumiy bazani bo'lishmaydi** va bir-birining kodini import qilmaydi. Yagona aloqa nuqtasi — `proto/cc01/v1/access.proto` (ADR-010). Chegara buzilishi kompilyatsiya xatosi bermagani uchun `test/contract/` testlari CI'da majburiy.

Buzilishlar CI'da `go-arch-lint` bilan tekshiriladi.

---

## 3. Client Protocol Specification

### 3.1 Daemon hayot sikli (bootstrap ketma-ketligi)

```
1. PREFLIGHT
   ├─ kernel versiya, BTF mavjudligi, CAP_NET_ADMIN/CAP_BPF tekshiruvi
   ├─ /dev/net/tun mavjudmi
   └─ xato → aniq remediation xabari (cc01 doctor formatida)

2. STATE LOAD
   ├─ /var/lib/cc01/state.json  (encrypted, node private key TPM'da)
   ├─ oxirgi NetworkMap snapshot (fail-static uchun)
   └─ yo'q bo'lsa → yangi kalit jufti generatsiya

3. CONTROL CONNECT
   ├─ mTLS gRPC → cp.cc01.io:443
   ├─ Register / Reauth  → node_cert (TTL 24h)
   └─ WatchNetworkMap stream ochiladi (since=last_version)

4. IPAM
   ├─ AllocateAddress(node_id) → 2a0X:XXXX:1::b/128 + tenant /64
   └─ lease_id saqlanadi, renew taymeri 6h

5. TUN SETUP  (§3.2)
6. ROUTE SETUP (§3.3)
7. eBPF LOAD  (§4)
8. IPC SERVER  → unix:///run/cc01/cc01.sock
9. DISCO START → STUN, endpoint e'lon qilish
10. PEER SESSIONS → lazy (birinchi paketda) yoki eager (tag bo'yicha)
11. READY → `cc01 status` "connected" ko'rsatadi
```

### 3.2 TUN interfeysini initsializatsiya qilish

**Algoritm (Linux):**

```go
// internal/daemon/tun/tun_linux.go
func Setup(cfg Config) (*Device, error) {
    // 1) Device yaratish — multi-queue, NUMA-aware
    dev, err := tun.CreateTUN("cc0", cfg.MTU /* 1280 */)
    //    IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE
    //    queue soni = min(runtime.NumCPU(), 8)

    // 2) Interfeysni ko'tarish
    link, _ := netlink.LinkByName("cc0")
    netlink.LinkSetMTU(link, cfg.MTU)
    netlink.LinkSetTxQLen(link, 1000)
    netlink.LinkSetUp(link)

    // 3) IPv6 manzillarni qo'shish
    //    - GUA /128 (public, IPAM'dan)
    //    - ULA /128 (ichki servis mesh)
    for _, a := range cfg.Addresses {
        netlink.AddrAdd(link, &netlink.Addr{
            IPNet: a, Flags: unix.IFA_F_NODAD | unix.IFA_F_PERMANENT,
        })
    }
    //    ⚠️ NODAD majburiy: overlay'da DAD ma'nosiz va 1s kechikish beradi

    // 4) sysctl tuning (faqat cc0 uchun)
    write("/proc/sys/net/ipv6/conf/cc0/disable_ipv6",       "0")
    write("/proc/sys/net/ipv6/conf/cc0/accept_ra",          "0")
    write("/proc/sys/net/ipv6/conf/cc0/autoconf",           "0")
    write("/proc/sys/net/ipv6/conf/cc0/forwarding",         "1") // subnet router uchun
    write("/proc/sys/net/ipv6/conf/all/accept_redirects",   "0")

    // 5) Offload sozlamalari (batching uchun)
    ethtool.SetFeature("cc0", "tx-udp-segmentation", true)  // GSO
    ethtool.SetFeature("cc0", "rx-gro-list",         true)

    // 6) Read/write goroutine'lari — har queue uchun bittadan
    //    vectored I/O: 128 ta paketgacha bitta syscall'da
}
```

**Bufer headroom'i (amalda topilgan majburiy talab).**

`Read`/`Write` chaqiruvlarida bufer boshida bo'sh joy qoldirilishi **shart**,
aks holda platforma `invalid offset` qaytaradi:

| Platforma | Talab | Nima uchun |
| --- | --- | --- |
| Linux | 10 bayt | virtio-net sarlavhasi (GSO/GRO yoqilganda) |
| macOS | 4 bayt | protokol oilasi (`AF_INET6`) |
| Windows | 0 | — |

`tun.Offset = 16` tanlandi: u hamma talabni qoplaydi va **`noise.HeaderSize`
ga teng**. Ya'ni datapath paketni shu headroom bilan o'qiydi, keyin kripto
qatlami cc01 sarlavhasini aynan shu joyga yozadi — paketni ko'chirish kerak
bo'lmaydi. `Device.NewBuffers()` to'g'ri o'lchamdagi buferlarni o'zi beradi.

> Bu xato faqat **haqiqiy qurilmada** chiqadi: konfiguratsiya, marshrut va
> o'qish mukammal ishlagan holda `Write` jimgina `n=0` qaytargan. Shuning
> uchun TUN qatlami uchun konteynerdagi imtiyozli test majburiy —
> `make test-linux`.

**Platformalar bo'yicha farqlar:**

| Platforma | Mexanizm | Cheklovlar |
| --- | --- | --- |
| Linux | `/dev/net/tun`, netlink | To'liq funksiya + eBPF |
| macOS | `utun` (BSD socket) | eBPF yo'q → PF filtri; `scutil` bilan DNS |
| Windows | Wintun (`wintun.dll`, imzolangan) | eBPF yo'q → WFP callout; `netsh` bilan marshrut |
| iOS/Android | `NEPacketTunnelProvider` / `VpnService` | Xotira limiti 15 MB → peer sonini cheklash |
| Docker/K8s | `CAP_NET_ADMIN` + `/dev/net/tun` mount | Yoki `hostNetwork` + `CAP_BPF` |

### 3.3 Marshrut jadvalini yangilash algoritmi

**Muammo:** overlay marshrutlari tizim marshrutlari bilan to'qnashmasligi va foydalanuvchi konfiguratsiyasini buzmasligi kerak.

**Yechim: alohida routing table + policy routing.**

```bash
# 1) Ajratilgan jadval (RT_TABLE = 51820)
ip -6 route add 2a0X:XXXX:1::/64 dev cc0 table 51820 proto static metric 100
ip -6 route add fd01:cc01::/32     dev cc0 table 51820 proto static

# 2) Policy rule — cc0'dan chiqmagan paketlar uchun
ip -6 rule add priority 5210 not fwmark 0xca01 lookup 51820
ip -6 rule add priority 5211 table main suppress_prefixlength 0   # loop oldini olish

# 3) Exit-node rejimi (butun trafik overlay orqali)
ip -6 route add ::/0 dev cc0 table 51820
#    fwmark 0xca01 → cc01d o'zi yuborayotgan paketlar (recursion oldini olish)
```

**Reconciliation loop (deklarativ, imperativ emas)** — ✅ `daemon/route`:

```
on NetworkMap change (turtki)  OR  every 30s (zaxira):
    desired = tenant_cidr + { peer.allowed_ips | base qamramagan }
    actual  = netlink.RouteList(table=51820, oif=cc0, proto=static)

    for r in desired - actual:  netlink.RouteAdd(r)     // AVVAL qo'shish
    for r in actual  - desired: netlink.RouteDel(r)     // KEYIN o'chirish

on Close():
    cleanup_all(table=51820, proto=static); ip rule del priority 5210,5211
```

Uchta qaror hujjatning dastlabki eskizidan farq qiladi:

**Davriylik 3 s emas, 30 s.** Haqiqiy signal — NetworkMap o'zgarishi, va u
turtki (`Poke`) bilan darhol keladi. Taymer faqat zaxira: yadro holati
bizdan so'ramasdan o'zgargan holatlar uchun. 3 soniyalik netlink so'rovi
hech narsa qo'shmaydi.

**Tenant `/64` ichidagi peer `/128` lariga alohida marshrut yozilmaydi.**
Ular bazaviy prefiks bilan allaqachon qamralgan; har bir peer uchun yozuv
qo'shish jadvalni node soniga chiziqli o'stiradi va birorta marshrutlash
qarorini o'zgartirmaydi. `cp-demo` da uch node bo'lsa ham jadvalda bitta
yozuv turadi.

**Qo'shish o'chirishdan oldin.** Teskari tartibda marshrut almashtirilayotgan
paytda trafik uchun marshrutsiz oyna ochiladi.

⚠️ **Uchta filtr ham majburiy.** `proto=static` bo'lmasa, ajratilgan jadvalga
qo'lda qo'shilgan marshrut "ortiqcha" ko'rinadi va o'chib ketadi — `ip route
add` sukut bo'yicha `RTPROT_BOOT` qo'yadi, biz `RTPROT_STATIC` yozamiz. Buni
`TestSetRoutes_LeavesForeignRoutesAlone` qo'riqlaydi.

**Konflikt aniqlash:** agar tenant `/64` foydalanuvchining LAN prefiksi bilan kesishsa (kam ehtimol IPv6'da, lekin ULA'da mumkin) — daemon `WARN` chiqaradi va marshrutni qo'shmaydi; `cc01 status` konfliktni ko'rsatadi.

### 3.4 Public IPv6 taqsimlash protokoli

**gRPC servis (`proto/cc01/v1/ipam.proto`):**

```protobuf
service IPAM {
  rpc AllocateAddress (AllocateRequest) returns (AllocateResponse);
  rpc RenewLease      (RenewRequest)    returns (RenewResponse);
  rpc ReleaseAddress  (ReleaseRequest)  returns (ReleaseResponse);
  rpc AllocateSubnet  (SubnetRequest)   returns (SubnetResponse); // subnet-router
}

message AllocateRequest {
  string node_id      = 1;   // SHA-256(pubkey), hex
  string tenant_id    = 2;
  string preferred    = 3;   // ixtiyoriy: oldingi manzilni so'rash (sticky)
  string region_hint  = 4;   // "tas" | "eu" | "apac"
  uint32 prefix_len   = 5;   // 128 (node) | 64 (subnet router) | 56 (enterprise)
  bytes  attestation  = 6;   // TPM quote / device posture, ixtiyoriy
}

message AllocateResponse {
  string address      = 1;   // "2a0X:XXXX:1::b/128"
  string tenant_cidr  = 2;   // "2a0X:XXXX:1::/64"
  string lease_id     = 3;
  int64  expires_at   = 4;   // unix ts
  string anchor_pop   = 5;   // "tas1"  ← BGP e'lon qiladigan PoP
  repeated string dns = 6;   // overlay DNS resolverlar
}
```

**Ijara holat mashinasi:**

```
   ┌──────┐  Allocate   ┌────────┐  t < 0.5·TTL   ┌────────┐
   │ FREE │ ──────────► │ ACTIVE │ ─────renew───► │ ACTIVE │
   └──────┘             └───┬────┘                └────────┘
      ▲                     │ TTL o'tdi (renew yo'q)
      │                     ▼
      │              ┌─────────────┐
      │  24h GC      │ QUARANTINE  │  ← eski marshrutlar, DNS kesh tozalanadi
      └──────────────┤  (24 soat)  │
                     └─────────────┘
```

**Qoidalar:**

1. **Sticky allocation:** node qayta ulanganda `preferred` maydonini yuboradi; agar manzil hali quarantine'da bo'lsa va o'sha nodega tegishli bo'lsa — qaytariladi. Bu IP o'zgarishini minimallashtiradi.
2. **Renew kadensiyasi:** TTL 72 soat, renew har 6 soat (TTL/12). 3 ta ketma-ket muvaffaqiyatsiz renew → `WARN`; TTL tugagach fail-static grace.
3. **Idempotentlik:** `Allocate` bir xil `(node_id, tenant_id)` uchun bir xil natija qaytaradi (agar aktiv ijara bo'lsa) — retry xavfsiz.
4. **Konsistentlik:** allocate → Raft commit → keyin javob. Commit bo'lmasa `UNAVAILABLE` qaytariladi, klient backoff bilan qayta uradi.
5. **BGP integratsiyasi:** yangi `/48` faollashganda `anchor_pop` BGP e'lonini yangilaydi. `/64` va `/128` e'lon qilinmaydi (aggregate `/48` yetarli).
6. **Reverse DNS:** `ip6.arpa` zonasi avtomatik yangilanadi (`<node>.<tenant>.cc01.io` PTR).

### 3.5 Peer sessiyasi va kalit rotatsiyasi

| Hodisa | Amal |
| --- | --- |
| Birinchi paket peer'ga | `handshake_init` (Noise IK), navbatga 1024 paketgacha buferlash |
| Handshake timeout | 5 s → qayta urinish (2 s, 4 s, 8 s... max 60 s) |
| Rekey trigger | `now - session_start > 120s` **yoki** `nonce > 2^60` **yoki** `handshake_attempts` |
| Rekey initiator | Faqat sessiyani boshlagan tomon (thundering herd oldini olish) |
| Eski sessiya | Yangi tasdiqlangandan keyin 5 s davomida qabul qilinadi (grace), keyin wipe |
| Peer revoked | CP `MapDelta{removed:[node_id]}` → sessiya darhol yopiladi, allowed_ips o'chiriladi |

**Replay himoyasi:** 2048-bitli sliding bitmap. `counter < window_start` → drop. `counter` allaqachon ko'rilgan → drop. Bu RFC 6479 algoritmi.

---
## 4. eBPF Program Architecture

### 4.1 Hook'lar va biriktirish nuqtalari

| Dastur | Hook | Interfeys | Rejim | Maqsad |
| --- | --- | --- | --- | --- |
| `xdp_filter` | `BPF_PROG_TYPE_XDP` | `eth0` (fizik) | native → generic fallback | DDoS scrub, blocklist, rate limit, redirect |
| `tc_ingress` | `BPF_PROG_TYPE_SCHED_CLS` | `cc0` (clsact ingress) | direct-action | Policy enforcement, accounting |
| `tc_egress` | `BPF_PROG_TYPE_SCHED_CLS` | `cc0` (clsact egress) | direct-action | Egress policy, MSS clamp, DSCP marking |
| `cgroup_sock` | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `/sys/fs/cgroup/cc01` | — | Ilova darajasidagi bind cheklovi (v1.1) |
| `sk_lookup` | `BPF_PROG_TYPE_SK_LOOKUP` | net namespace | — | Bitta portni bir nechta socket'ga taqsimlash (v1.2) |

**Yuklash strategiyasi:**

```
1. BTF mavjudligini tekshirish (/sys/kernel/btf/vmlinux)
2. CO-RE relokatsiya bilan yuklash (cilium/ebpf → bpf2go generatsiya)
3. XDP native rejimda attach urinish
   ├─ muvaffaqiyat → metric: xdp_mode="native"
   └─ EOPNOTSUPP → generic (skb) rejim, WARN log, metric: xdp_mode="generic"
4. Map'larni /sys/fs/bpf/cc01/ ga pin qilish
   → daemon restart bo'lsa ham filtrlash uzilmaydi (fail-static)
5. Program pin + link pin (BPF_LINK) → avtomatik detach'dan himoya
```

### 4.2 BPF map strukturalari

**`internal/bpf/include/cc01_maps.h` — yagona haqiqat manbai:**

```c
/* ─────────────────── 1. POLICY (Zero-Trust ACL) ─────────────────── */
struct policy_key {
    __u32 prefixlen;            /* LPM: 0..(128+128+16+16) bitgacha */
    __u8  src_addr[16];         /* IPv6 src prefiks */
    __u8  dst_addr[16];         /* IPv6 dst prefiks */
    __u16 dport;                /* 0 = any */
    __u8  proto;                /* IPPROTO_TCP/UDP/ICMPV6, 0 = any */
    __u8  _pad;
} __attribute__((packed));

struct policy_value {
    __u8  verdict;              /* 0=DROP 1=ALLOW 2=LOG_ALLOW 3=REDIRECT */
    __u8  flags;                /* bit0=count bit1=sample bit2=ratelimit */
    __u16 rule_id;              /* audit uchun — CP'dagi qoida ID'si */
    __u32 redirect_ifindex;
    __u64 hit_count;            /* atomik oshiriladi */
} __attribute__((packed));

struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE);
         __type(key, struct policy_key); __type(value, struct policy_value);
         __uint(max_entries, 65536);
         __uint(map_flags, BPF_F_NO_PREALLOC);
         __uint(pinning, LIBBPF_PIN_BY_NAME);
} cc01_policy_v6 SEC(".maps");

/* ─────────────────── 2. CONNTRACK (fast path) ─────────────────── */
struct ct_key {   /* 5-tuple */
    __u8  src[16]; __u8 dst[16];
    __u16 sport;   __u16 dport;
    __u8  proto;   __u8 _pad[3];
} __attribute__((packed));

struct ct_value {
    __u64 last_seen_ns;
    __u64 packets; __u64 bytes;
    __u8  state;                /* 0=NEW 1=ESTABLISHED 2=CLOSING */
    __u8  verdict;              /* keshlangan hukm — policy lookup'ni tejaydi */
    __u16 rule_id;
    __u32 _pad;
} __attribute__((packed));

struct { __uint(type, BPF_MAP_TYPE_LRU_HASH);
         __type(key, struct ct_key); __type(value, struct ct_value);
         __uint(max_entries, 1048576);   /* 1M sessiya ≈ 80 MB */
} cc01_conntrack SEC(".maps");

/* ─────────────────── 3. RATE LIMIT (token bucket) ─────────────── */
struct rl_key   { __u8 prefix[8]; };   /* src /64 bo'yicha guruhlash */
struct rl_value {
    __u64 tokens_pps;   __u64 tokens_bps;
    __u64 last_refill_ns;
    __u64 dropped;
};
struct { __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
         __type(key, struct rl_key); __type(value, struct rl_value);
         __uint(max_entries, 262144);
} cc01_ratelimit SEC(".maps");

/* ─────────────────── 4. BLOCKLIST ─────────────────── */
struct bl_value { __u64 expires_ns; __u32 reason; __u32 hits; };
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH);
         __type(key, struct in6_addr); __type(value, struct bl_value);
         __uint(max_entries, 1048576);
} cc01_blocklist SEC(".maps");

/* ─────────────────── 5. EVENT RING BUFFER ─────────────────── */
struct event {
    __u64 ts_ns;
    __u8  src[16]; __u8 dst[16];
    __u16 sport;   __u16 dport;
    __u8  proto;   __u8 verdict; __u8 stage; __u8 _pad;
    __u16 rule_id; __u16 reason;
    __u32 pkt_len;
};
struct { __uint(type, BPF_MAP_TYPE_RINGBUF);
         __uint(max_entries, 16 * 1024 * 1024);  /* 16 MB, power of 2 */
} cc01_events SEC(".maps");

/* ─────────────────── 6. CONFIG (runtime tuning) ─────────────── */
struct cc01_config {
    __u32 rl_pps_limit;      __u32 rl_bps_limit;
    __u32 syn_cookie_thresh; __u32 flags;   /* bit0=enforce bit1=log_all bit2=panic_mode */
    __u16 wg_port;           __u16 sample_rate;
    __u32 _pad;
};
struct { __uint(type, BPF_MAP_TYPE_ARRAY);
         __type(key, __u32); __type(value, struct cc01_config);
         __uint(max_entries, 1);
} cc01_cfg SEC(".maps");

/* ─────────────────── 7. STATS (per-CPU counters) ─────────────── */
enum stat_idx {
    S_TOTAL=0, S_PASS, S_DROP_BLOCKLIST, S_DROP_RATELIMIT, S_DROP_POLICY,
    S_DROP_MALFORMED, S_REDIRECT, S_SYN_COOKIE, S_CT_HIT, S_CT_MISS, S__MAX
};
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
         __type(key, __u32); __type(value, __u64);
         __uint(max_entries, S__MAX);
} cc01_stats SEC(".maps");

/* ─────────────────── 8. AF_XDP REDIRECT ─────────────── */
struct { __uint(type, BPF_MAP_TYPE_XSKMAP);
         __type(key, __u32); __type(value, __u32);
         __uint(max_entries, 64);   /* RX queue soni */
} cc01_xsks SEC(".maps");
```

**Xotira byudjeti (klient, default):**

| Map | Yozuvlar | Taxminiy hajm |
| --- | --- | --- |
| `cc01_policy_v6` | 65 536 | ~4 MB |
| `cc01_conntrack` | 1 048 576 | ~80 MB (server), 65 536 → 5 MB (desktop) |
| `cc01_ratelimit` | 262 144 × nCPU | ~30 MB |
| `cc01_blocklist` | 1 048 576 | ~40 MB |
| `cc01_events` | ring | 16 MB |
| **Jami (desktop profil)** | | **< 48 MB** |
| **Jami (edge profil)** | | **~180 MB** |

### 4.3 XDP dastur mantiqi (pseudokod)

```c
SEC("xdp")
int cc01_xdp_filter(struct xdp_md *ctx)
{
    void *data = (void*)(long)ctx->data, *end = (void*)(long)ctx->data_end;
    STAT_INC(S_TOTAL);

    /* ── Stage 0: SANITY ────────────────────────────── */
    struct ethhdr *eth = data;
    if ((void*)(eth+1) > end) { STAT_INC(S_DROP_MALFORMED); return XDP_DROP; }
    if (eth->h_proto != bpf_htons(ETH_P_IPV6)) return XDP_PASS;   /* v4 → stack */

    struct ipv6hdr *ip6 = (void*)(eth+1);
    if ((void*)(ip6+1) > end) { STAT_INC(S_DROP_MALFORMED); return XDP_DROP; }

    struct cc01_config *cfg = bpf_map_lookup_elem(&cc01_cfg, &(__u32){0});
    if (!cfg) return XDP_PASS;                    /* fail-open: config yo'q */

    /* ── Stage 1: BLOCKLIST ─────────────────────────── */
    struct bl_value *bl = bpf_map_lookup_elem(&cc01_blocklist, &ip6->saddr);
    if (bl && bl->expires_ns > bpf_ktime_get_ns()) {
        __sync_fetch_and_add(&bl->hits, 1);
        STAT_INC(S_DROP_BLOCKLIST);
        return XDP_DROP;                          /* eng arzon yo'l */
    }

    /* ── Stage 2: RATE LIMIT (token bucket, /64 bo'yicha) ── */
    if (!rate_limit_ok(&ip6->saddr, ctx_len(ctx), cfg)) {
        STAT_INC(S_DROP_RATELIMIT);
        emit_event(ctx, STAGE_RATELIMIT, V_DROP, R_PPS_EXCEEDED);
        return XDP_DROP;                          /* + auto-blocklist trigger */
    }

    /* ── L4 header parsing (extension header'lardan o'tish) ── */
    struct l4info l4;
    if (parse_l4(ip6, end, &l4) < 0) { STAT_INC(S_DROP_MALFORMED); return XDP_DROP; }

    /* ── Stage 3: ANTI-DDoS ─────────────────────────── */
    if (l4.proto == IPPROTO_TCP && l4.syn && !l4.ack) {
        if (syn_rate_exceeded(cfg)) return xdp_syn_cookie_reply(ctx, ip6, &l4);
    }
    if (l4.proto == IPPROTO_UDP && is_amplification_port(l4.sport)) {
        STAT_INC(S_DROP_POLICY); return XDP_DROP;   /* 53/123/1900/11211 */
    }

    /* ── Stage 4: FAST PATH (conntrack + cc01 datapath) ── */
    if (l4.proto == IPPROTO_UDP && l4.dport == cfg->wg_port) {
        STAT_INC(S_REDIRECT);
        return bpf_redirect_map(&cc01_xsks, ctx->rx_queue_index, XDP_PASS);
        /* AF_XDP zero-copy → cc01d userspace; fallback XDP_PASS */
    }
    struct ct_key ck; build_ct_key(&ck, ip6, &l4);
    struct ct_value *ct = bpf_map_lookup_elem(&cc01_conntrack, &ck);
    if (ct && ct->state == CT_ESTABLISHED) {
        ct->last_seen_ns = bpf_ktime_get_ns();
        __sync_fetch_and_add(&ct->packets, 1);
        STAT_INC(S_CT_HIT);
        return ct->verdict ? XDP_PASS : XDP_DROP;   /* policy lookup'ni tejaymiz */
    }
    STAT_INC(S_CT_MISS);

    /* ── Stage 5: POLICY (LPM trie, deny-by-default) ── */
    struct policy_key pk; build_policy_key(&pk, ip6, &l4);
    struct policy_value *pv = bpf_map_lookup_elem(&cc01_policy_v6, &pk);

    __u8 verdict = V_DROP;  __u16 rid = 0;
    if (pv) { verdict = pv->verdict; rid = pv->rule_id;
              __sync_fetch_and_add(&pv->hit_count, 1); }

    if (!(cfg->flags & F_ENFORCE))                /* dry-run rejimi */
        { emit_event(ctx, STAGE_POLICY, verdict, rid); return XDP_PASS; }

    if (verdict == V_DROP) {
        STAT_INC(S_DROP_POLICY);
        emit_event(ctx, STAGE_POLICY, V_DROP, rid);
        return XDP_DROP;
    }

    ct_insert(&ck, verdict, rid);                 /* keyingi paketlar fast path'da */
    STAT_INC(S_PASS);
    if (verdict == V_LOG_ALLOW) emit_event(ctx, STAGE_POLICY, V_ALLOW, rid);
    return XDP_PASS;
}
```

### 4.4 Verdict qoidalari va semantikasi

| Verdict | XDP qaytaruvchi | Semantika | Qachon |
| --- | --- | --- | --- |
| `XDP_DROP` | 0 | Paket yo'q qilinadi, javob yo'q | Blocklist, rate limit, policy deny |
| `XDP_PASS` | 2 | Kernel stack'ga | Ruxsat etilgan, cc01 bo'lmagan trafik |
| `XDP_TX` | 3 | O'sha interfeysdan qaytariladi | SYN cookie javobi, relay reflect |
| `XDP_REDIRECT` | 4 | AF_XDP socket / boshqa NIC | cc01 datapath, edge relay forward |
| `XDP_ABORTED` | 0 | Xato — tracepoint + alert | Faqat bug holatida (CI'da 0 bo'lishi shart) |

**Muhim qoidalar:**

1. **Fail-open vs fail-closed:** config map yo'q bo'lsa `XDP_PASS` (tarmoqni butunlay o'ldirmaslik uchun). Policy map yo'q bo'lsa `enforce` rejimida `XDP_DROP`.
2. **Dry-run majburiy:** har qanday yangi policy avval `enforce=false` bilan ≥ 1 soat ishlaydi; `would_drop` metrikasi tekshiriladi, keyin enforce.
3. **Panic mode:** `flags |= F_PANIC` — faqat allowlist'dagi manzillar o'tadi (og'ir hujum paytida operator qo'li bilan yoqadi).
4. **Verifier byudjeti:** har bir dastur < 4096 instruksiya (eski kernellar bilan moslik), loop'lar `bpf_loop()` yoki `#pragma unroll` bilan.

### 4.5 Userspace ↔ eBPF sinxronizatsiyasi

```
NetworkMap / Policy o'zgardi
        │
        ▼
[policy compiler]  ACL → (src,dst,proto,port,verdict) tuple'lar
        │
        ▼
[differ]  desired_set vs current_map_contents
        │           ├─ qo'shish:  BPF_MAP_UPDATE_ELEM (BPF_NOEXIST)
        │           ├─ yangilash: BPF_MAP_UPDATE_ELEM (BPF_EXIST)
        │           └─ o'chirish: BPF_MAP_DELETE_ELEM
        ▼
[atomic swap]  katta o'zgarishda: yangi map yaratiladi → BPF_MAP_TYPE_PROG_ARRAY
               yoki map-in-map (BPF_MAP_TYPE_HASH_OF_MAPS) orqali atomik almashish
        │
        ▼
[verify]  ✅ hit_count'lar oqyaptimi? ❌ rollback (oldingi map versiyasi 5 min saqlanadi)
```

**Ring buffer iste'moli:** alohida goroutine, `ringbuf.Reader.Read()` bloklanuvchi; eventlar batch'lanadi (100 ta yoki 100 ms) → Prometheus + log sink. Buffer to'lsa eventlar yo'qoladi (`ringbuf_lost` metrikasi) — bu qabul qilinadi, paket filtrlash to'xtamaydi.

---

## 5. Tunneling Subsystem — API & CLI

### 5.1 CLI buyruqlar daraxti

`✅` — amalga oshirilgan, `⏳` — rejalashtirilgan:

```
cc01
├── up [--auth-key KEY] [--accept-routes] [--exit-node NODE] [--hostname NAME]   ✅¹
├── down                                     # mesh'dan uzilish (daemon ishlaydi)  ✅
├── status [--json] [--watch]                                                    ✅
├── doctor                                   # preflight/diagnostika hisoboti     ✅
├── version                                                                      ✅
│    ¹ bayroqlar hali yo'q: konfiguratsiya `cc01d` ga beriladi
│
├── tunnel                                   # ── ngrok funksiyasi ──
│   ├── http <port|url> [--subdomain S] [--domain D] [--auth user:pass]
│   │                   [--host-header H] [--basic-auth] [--oauth google]
│   │                   [--request-header-add K:V] [--compression]
│   ├── tcp  <port>     [--remote-port N] [--region tas1] [--ip-restriction CIDR]
│   ├── udp  <port>     [--remote-port N] [--region tas1]
│   ├── tls  <port>     [--domain D] [--terminate-at edge|client]
│   ├── list [--json]
│   ├── stop <tunnel-id|all>
│   └── inspect <tunnel-id>                  # so'rovlar oqimi (ngrok inspector analogi)
│
├── peer                                     # ── mesh boshqaruvi ──
│   ├── list [--json] [--online]                                                 ✅
│   ├── ping <node|ipv6> [--count N] [--path direct|relay]                       ⏳
│   ├── route <node>                         # joriy yo'lni ko'rsatish            ⏳
│   └── forget <node>                                                            ⏳
│
├── ip                                       # ── IPv6 ──
│   ├── show                                 # joriy GUA/ULA, lease TTL, anchor PoP
│   ├── renew
│   └── subnet advertise <cidr>              # subnet router rejimi
│
├── firewall                                 # ── eBPF policy ──
│   ├── add   --allow|--deny --src CIDR --dst CIDR --proto tcp --port 443 [--comment C]
│   ├── del   <rule-id>
│   ├── list  [--json] [--stats]             # hit counterlar bilan
│   ├── test  --src A --dst B --proto tcp --port 443   # qaysi qoida ishlaydi?
│   ├── mode  enforce|dry-run|panic
│   └── flush [--force]
│
├── relay
│   ├── list                                 # mavjud relaylar + RTT
│   └── ping [--all]
│
├── cert
│   ├── list                                 # ACME sertifikatlar
│   └── renew <domain>
│
├── logs [--follow] [--level] [--component]
├── metrics                                  # Prometheus formatida dump
└── config
    ├── get <key> · set <key> <value> · show
```

**Namuna sessiya:**

```bash
$ cc01 up --auth-key tskey-abc123
✔ Preflight: kernel 6.8.0, BTF ✓, CAP_BPF ✓
✔ Control plane: cp.cc01.io (tas1, 3 ms)
✔ IPv6 allocated: 2a0X:1234:1::b7f2/128  (tenant 2a0X:1234:1::/64, anchor tas1)
✔ TUN cc0 up, MTU 1280
✔ eBPF: xdp_filter attached (native), 42 policy rules
✔ Peers: 12 discovered, 3 active

$ cc01 tunnel http 8080 --subdomain myapp
✔ Tunnel started
  URL      https://myapp.tas.cc01.io  →  http://localhost:8080
  Region   tas1 (TasIX)     Latency 2.4 ms
  TLS      auto (Let's Encrypt, expires 2026-11-18)
  Inspect  http://127.0.0.1:4040

$ cc01 peer ping node-db-01
node-db-01 (2a0X:1234:1::4c1a) via DIRECT (udp 213.x.x.x:41022)
  seq=0  rtt=1.82ms   seq=1  rtt=1.79ms   seq=2  rtt=1.91ms
  --- 3 packets, 0% loss, path=direct, mtu=1280, session_age=41s

$ cc01 firewall add --deny --src ::/0 --dst 2a0X:1234:1::4c1a/128 --proto tcp --port 5432 \
    --comment "DB faqat API'dan"
✔ Rule #17 added (dry-run mode — enforce uchun: cc01 firewall mode enforce)
```

### 5.2 Daemon IPC interfeysi

| Parametr | Qiymat |
| --- | --- |
| Transport | UNIX Domain Socket: `/run/cc01/cc01.sock` |
| Protokol | gRPC (protobuf) |
| Ruxsatlar | `0660`, egasi `root:cc01` — CLI ishlatuvchilar `cc01` guruhida |
| Autentifikatsiya | `SO_PEERCRED` (uid/gid tekshiruvi) + rol tekshiruvi |
| Windows | Named pipe `\\.\pipe\cc01` |
| Kuzatuv | `WatchStatus` — server-streaming (real-time TUI uchun) |

**`proto/cc01/v1/daemon.proto` — hozirgi holat.** Faqat *o'qish* buyruqlari
amalga oshirilgan: ular ishlab turgan demonni ko'rish imkonini beradi va
yozish operatsiyalaridan farqli o'laroq holatni o'zgartirmaydi, shuning
uchun ular birinchi bo'lib qurildi.

```protobuf
service DaemonService {
  rpc Up          (UpRequest)          returns (UpResponse);              // ✅
  rpc Down        (DownRequest)        returns (DownResponse);            // ✅
  rpc Status      (StatusRequest)      returns (StatusResponse);          // ✅
  rpc WatchStatus (WatchStatusRequest) returns (stream WatchStatusResponse); // ✅
  rpc Peers       (PeersRequest)       returns (PeersResponse);           // ✅
  rpc Doctor      (DoctorRequest)      returns (DoctorResponse);          // ✅
}
```

**`Up` va `Down` ning shartnomasi assimetrik**, va bu ataylab:

`Down` ikkinchi marta chaqirilsa **xato emas** — "tushirilgan bo'lsin" degan
talab allaqachon bajarilgan. Javobdagi `already_down` bayrog'i hech narsa
o'zgarmaganini aytadi. `Up` esa allaqachon ko'tarilgan mesh'da
`ALREADY_EXISTS` qaytaradi: konfiguratsiya farq qilishi mumkin va uni
jimgina e'tiborsiz qoldirish yanglish bo'lardi.

Demon endi mesh'dan uzoqroq yashaydi: IPC soketi mesh ko'tarilishidan
**oldin** ochiladi, shunda nosozlikni aynan kerak bo'lgan paytda —
ulanish qurilmayotganda — `cc01 status` va `cc01 doctor` bilan ko'rish
mumkin. `cc01d -down` bayrog'i mesh'ni ko'tarmasdan ishga tushiradi.

`StatusResponse` mesh holatini beradi (`connected`, `node_id`, `address`,
`interface`, `listen_port`, `endpoints`, `control_plane`, `relay_id`,
`peer_count`, `uptime_seconds`). `PeerStatus` har bir peer uchun **yo'l
holatini** ochadi — `path` (`direct`/`relay`/`none`), `path_state`
(ARCHITECTURE.md §6.2 holat mashinasi) va `rtt_micros`. Bu maydonlarsiz
relay→direct ko'tarilishini tashqaridan kuzatib bo'lmaydi.

`Check.remediation` — xato bo'lganda "nima qilishim kerak" degan savolga
javob; §3.1 talabi.

**Hali qurilmagan** — ikkalasi ham o'z quyi tizimini kutadi:

```protobuf
service Tunnels {                                   // ⏳ §5.3 bilan birga
  rpc Open   (OpenTunnelRequest)  returns (TunnelInfo);
  rpc Close  (CloseTunnelRequest) returns (CloseTunnelResponse);
  rpc List   (ListTunnelsRequest) returns (ListTunnelsResponse);
  rpc Inspect(InspectRequest)     returns (stream RequestTrace);
}

service Firewall {                                  // ⏳ §4 (eBPF) bilan birga
  rpc AddRule  (AddRuleRequest)   returns (RuleResponse);
  rpc DelRule  (DelRuleRequest)   returns (RuleResponse);
  rpc ListRules(ListRulesRequest) returns (ListRulesResponse);
  rpc TestRule (TestRuleRequest)  returns (TestRuleResponse);
  rpc SetMode  (SetModeRequest)   returns (SetModeResponse);
}
```

**Soket yo'li uzunligi.** `sockaddr_un.sun_path` qat'iy o'lchamda —
Linux'da 108 bayt, macOS/BSD'da 104. Chegaradan oshsa yadro
`invalid argument` qaytaradi va sababni ko'rsatmaydi, shuning uchun
`ipc.Listen` yo'lni oldindan o'lchaydi va tushunarli xato beradi.

**Xato kodlari (gRPC status → CLI exit code):**

| gRPC kod | CLI exit | Ma'nosi |
| --- | --- | --- |
| `OK` | 0 | Muvaffaqiyat |
| `UNAVAILABLE` | 10 | Daemon ishlamayapti (`systemctl start cc01d`) |
| `PERMISSION_DENIED` | 11 | `cc01` guruhida emas |
| `ALREADY_EXISTS` | 12 | Subdomain band |
| `RESOURCE_EXHAUSTED` | 13 | Tarif limiti (tunnel soni / bandwidth) |
| `FAILED_PRECONDITION` | 14 | Mesh'ga ulanmagan (`cc01 up` kerak) |
| `INVALID_ARGUMENT` | 2 | Noto'g'ri parametr |

### 5.2.1 O'rnatish va systemd

`make package` bitta tavsifdan (`deploy/packaging/nfpm.yaml`) `amd64` va
`arm64` uchun `deb` va `rpm` quradi. nfpm tanlandi, chunki
`dpkg-buildpackage` va `rpmbuild` ikki xil host muhitini talab qiladi —
nfpm esa konteynerda ishlaydi va paketni macOS'dan ham qurish mumkin.

Paket nima o'rnatadi:

| Fayl | Vazifasi |
| --- | --- |
| `/usr/bin/cc01d`, `/usr/bin/cc01` | demon va CLI |
| `/lib/systemd/system/cc01d.service` | unit (S-5, S-6 hardening) |
| `/etc/cc01/cc01d.env` | konfiguratsiya, `0600`, yangilanishda **saqlanadi** |
| `/usr/lib/sysusers.d/cc01.conf` | `cc01` guruhi |
| `/usr/lib/tmpfiles.d/cc01.conf` | `/run/cc01` papkasi |
| `/usr/lib/cc01/cc01-cleanup` | `ExecStopPost` — halokatdan keyingi tozalash |

**Demon ataylab avtomatik yoqilmaydi.** Unga node kaliti va CP manzili
kerak, ular esa o'rnatishdan keyin hali bo'sh — avtomatik yoqilsa
foydalanuvchi faqat xato logini olardi. `postinstall` keyingi qadamlarni
ko'rsatadi.

**Soket egaligi.** `0660` ning o'zi yetarli emas: soket `root:root`
bo'lib qolsa, `cc01` guruhidagi foydalanuvchi ham ulana olmaydi va CLI
bergan "demon guruhiga qo'shiling" maslahati ishlamaydi. Demon soketni
`cc01` guruhiga o'tkazadi; guruh bo'lmasa (konteyner, paketsiz
o'rnatish) buni logga yozadi va faqat root ulana oladi.

**Root shart emas.** `CAP_NET_ADMIN` bilan demon `uid≠0` da ham TUN
yaratadi va marshrut qo'yadi — konteynerda `setcap cap_net_admin+ep`
va oddiy foydalanuvchi bilan tekshirilgan. `cc01 doctor` aynan shu
maslahatni beradi.

`make package-verify` paketni toza Debian konteyneriga o'rnatib
tekshiradi: fayllar joyidami, guruh yaratildimi, `systemd-analyze
verify` unit'dan norozimi, demon ishlamayotganda CLI 10-kod
qaytaradimi, o'chirishdan keyin konfiguratsiya saqlanadimi.

### 5.3 Tunnel data plane protokoli

```
Edge ↔ Klient: bitta uzun yashovchi QUIC connection, ko'p stream

  Stream 0 (bidirectional, control):
      OPEN_TUNNEL, TUNNEL_READY, CLOSE_TUNNEL, PING/PONG (15s), STATS_REPORT
  Stream N (har bir foydalanuvchi so'rovi/ulanishi uchun yangi):
      HTTP:  frame{stream_open, tunnel_id, method, path, headers} → body chunks
      TCP:   frame{stream_open, tunnel_id, client_ip} → xom baytlar
      UDP:   QUIC DATAGRAM frame (datagram chegaralari saqlanadi), session_id bilan
```

| Mexanizm | Tafsilot |
| --- | --- |
| Flow control | QUIC'ning o'z oynasi + per-tunnel limit (`max_conns`, `bandwidth`) |
| Backpressure | Klient sekin bo'lsa → edge `429` yoki TCP `RST`, hech qachon cheksiz bufer emas |
| Reconnect | 0-RTT QUIC resumption; tunnel URL 5 daqiqa saqlanadi (reserved) |
| Header injection | `X-Forwarded-For`, `X-Forwarded-Proto`, `CC01-Client-Region` |
| WebSocket | HTTP Upgrade → xom stream rejimiga o'tish |
| gRPC | HTTP/2 passthrough, trailer'lar saqlanadi |

---

## 6. Access Server (Account Plane) — .NET

> Arxitektura konteksti: `ARCHITECTURE.md` §3.4. Qaror asosi: `adr/ADR-009.md`.

### 6.1 Hozirgi holat

`access-server/` — `dotnet new webapi` shabloni ustiga qurilgan skelet. Ishga tushirishdan oldin tuzatilishi kerak bo'lgan narsalar:

| # | Muammo | Tuzatish | Holat |
| --- | --- | --- | --- |
| A-1 | Qatlamlar orasida `ProjectReference` **yo'q** — `Api` `Domain`ni ko'rmaydi | `Api → Application → Domain`, `Infrastructure → Application` | ✅ |
| A-2 | `AccessServer.Insfrastructure` — nomida xato (`Insfrastructure`) | `AccessServer.Infrastructure` ga qayta nomlash (papka, csproj, namespace, `.slnx`) | ✅ |
| A-3 | `WeatherForecast.cs`, `WeatherForecastController.cs`, `Class1.cs` — shablon qoldig'i | O'chirish | ✅ |
| A-4 | `User.Password` — ochiq parol maydoni taassurotini beradi | `PasswordHash` + PBKDF2-SHA256, 210k iteratsiya | ✅ |
| A-5 | `GithubToken` / `GoogleToken` — OAuth access tokenini saqlash | `GithubId` / `GoogleId` (provider subject) bilan almashtirish | ✅ |
| A-6 | `UserToken` token va subdomainni bitta yozuvda birlashtirgan | `ApiToken` va `Subdomain` sifatida ajratish | ✅ |
| A-7 | DB, migratsiya, connection string yo'q | EF Core + Npgsql, `dotnet ef migrations` | ✅ |
| A-8 | `UserToken.ExpiresIn` — `TimeSpan` (nisbiy) | `ExpiresAt` — `DateTimeOffset` (absolyut); nisbiy muddat saqlash renew mantiqini noaniq qiladi | ✅ |

Qo'shimcha qarorlar (kod yozilayotganda qabul qilingan):

| Qaror | Sabab |
| --- | --- |
| `Directory.Build.props` + `Directory.Packages.props` | Umumiy sozlamalar va paket versiyalari bitta joyda; `.csproj` fayllari qisqa |
| `TreatWarningsAsErrors` yoqilgan | §7.4 talabi; hozir 0 warning bilan quriladi |
| **snake_case** naming (`EFCore.NamingConventions`) | Postgres'da qo'shtirnoqli identifikatorlardan qutulish; `psql` va xom SQL bilan ishlash oson |
| Enumlar **matn** sifatida saqlanadi | Bazaga qarab ma'no tushunarli; enum tartibi o'zgarsa ma'lumot buzilmaydi |
| `TimeProvider` inyeksiya qilinadi | `CreatedAt`/`UpdatedAt` `SaveChanges`da markazda qo'yiladi va testda soxtalashtiriladi |
| `dotnet-ef` **lokal tool** (`dotnet-tools.json`) | Versiya repoda qayd etiladi; CI va ishlab chiquvchida bir xil |
| `IDesignTimeDbContextFactory` | Migratsiya Api hostiga, DI'ga va sirlarga bog'lanmaydi |

### 6.2 Domen modeli (EF Core)

```csharp
public abstract class Entity {
    public int Id { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

// Izolyatsiya chegarasi. Token, subdomain va kvota TENANTGA tegishli.
public sealed class Tenant : Entity {
    public required string Slug { get; set; }            // "t_9f3a", unique
    public required string Name { get; set; }
    public PlanCode Plan { get; set; }                   // Free | Pro | Enterprise
    public TenantStatus Status { get; set; }
    public ICollection<User> Users { get; set; } = [];
    public ICollection<ApiToken> Tokens { get; set; } = [];
    public ICollection<Subdomain> Subdomains { get; set; } = [];
}

public sealed class User : Entity {
    public int TenantId { get; set; }
    public Tenant Tenant { get; set; } = null!;          // nav — `required` EMAS
    public required string FullName { get; set; }
    public required string Email { get; set; }           // unique index
    public string? PasswordHash { get; set; }            // OAuth-only bo'lsa null
    public string? GithubId { get; set; }                // provider `sub`
    public string? GoogleId { get; set; }
    public DateTimeOffset? EmailVerifiedAt { get; set; }
    public UserStatus Status { get; set; }
    public bool Subscribe { get; set; }
}

public sealed class ApiToken : Entity {
    public int TenantId { get; set; }
    public Tenant Tenant { get; set; } = null!;
    public int CreatedByUserId { get; set; }             // audit uchun
    public required string Prefix { get; set; }          // "cc01_live_a1b2" — indeksli qidiruv
    public required byte[] TokenHash { get; set; }       // SHA-256(to'liq token)
    public required string Name { get; set; }            // "laptop", "ci-runner"
    public DateTimeOffset? LastUsedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }       // absolyut, TimeSpan emas
    public DateTimeOffset? RevokedAt { get; set; }
}

public sealed class Subdomain : Entity {
    public int TenantId { get; set; }
    public Tenant Tenant { get; set; } = null!;
    public required string Name { get; set; }            // unique, lowercase
    public SubdomainStatus Status { get; set; }          // Reserved | Active | Released
    public DateTimeOffset? ReservedUntil { get; set; }   // free tarifda muddatli
}
```

**Navigatsiya xossalari `required` emas** (`= null!`): EF ularni o'zi to'ldiradi. `required User User` deb yozilsa har bir entity yaratishda bog'liq obyektni majburan yuklash kerak bo'ladi — bu mavjud `UserToken` kodidagi xato.

`CustomDomain`, `Plan`, `Subscription`, `UsageRecord`, `AuditEvent` — Faza 1/3 da (§8). Faza 0 da tarif limitlari `PlanCode` enumidan kod ichidagi jadval orqali olinadi; to'liq `Plan`/`Subscription` entity'lari Faza 1 da.

**Indekslar (majburiy):** `Tenant.Slug` unique · `User.Email` unique · `ApiToken.Prefix` unique · `Subdomain.Name` unique · `ApiToken.TenantId` · `Subdomain.TenantId` · `UsageRecord (TenantId, WindowStart)`.

### 6.3 Token formati

```
cc01_live_a1b2c3d4_<32 bayt base62 sir>
└──┬───┘ └───┬───┘ └──────────┬───────┘
 muhit    prefiks (indeks)   sir (faqat bir marta ko'rsatiladi)
```

| Qoida | Sabab |
| --- | --- |
| Bazada faqat `SHA-256(to'liq token)` saqlanadi | Baza sizib chiqsa token ishlatib bo'lmaydi |
| Qidiruv `Prefix` bo'yicha, keyin hash **doimiy vaqtda** solishtiriladi | Timing attack'ning oldini olish |
| Token opaque, JWT emas | Bekor qilish darhol kuchga kirishi kerak; JWT'ni chaqirib olib bo'lmaydi |
| Muhit prefiksi (`live`/`test`) | Xato bilan prod tokenini test'da ishlatishning oldini oladi |
| Loglarga faqat `Prefix` yoziladi | To'liq token hech qachon logda bo'lmaydi |

### 6.4 API sirti

**Public REST** (`/v1/*`, dashboard va CLI uchun). `✅` — amalga oshirilgan va testlar bilan qoplangan:

```
✅ POST   /v1/auth/register            {fullName, email, password, subscribe}
✅ POST   /v1/auth/login               {email, password} → JWT
✅ POST   /v1/auth/verify-email        {token}
   POST   /v1/auth/refresh
✅ GET    /v1/auth/oauth/{github|google}          → provayderga redirect
✅ GET    /v1/auth/oauth/{provider}/callback      → handler (ASP.NET Core)
✅ GET    /v1/auth/oauth/complete                 → JWT beradi

   GET    /v1/me
✅ GET    /v1/tokens                   ro'yxat (prefiks, nom, oxirgi ishlatilgan)
✅ POST   /v1/tokens                   {name, expiresAt?} → sir bir marta qaytariladi
✅ DELETE /v1/tokens/{id}              bekor qilish (darhol)

✅ GET    /v1/subdomains
✅ POST   /v1/subdomains               {name} → egalik
✅ DELETE /v1/subdomains/{id}          bo'shatish (karantinga o'tadi)

   GET    /v1/domains                  custom domenlar
   POST   /v1/domains                  {fqdn} → TXT verifikatsiya tokeni
   POST   /v1/domains/{id}/verify

   GET    /v1/usage?from=&to=          bayt, ulanish, tunnel-soat
   GET    /v1/plan
```

Qolgan endpointlar Faza 1/3 da (§8).

**Xato → HTTP status xaritasi** bitta joyda: `AccessServer.Api/Common/ResultExtensions.cs`. Noma'lum kod uchun zaxira — `400`.

**Operatsion endpointlar** (autentifikatsiyasiz, orkestrator uchun):

```
GET    /healthz    liveness  — jarayon tirikmi; bazaga TEGMAYDI
GET    /readyz     readiness — baza javob beradimi; 503 qaytarishi mumkin
```

Ajratish muhim: baza qisqa muddatga yiqilganda jarayonni qayta ishga tushirish
muammoni hal qilmaydi, faqat trafikni to'xtatish kerak. `/healthz` bazaga
bog'liq bo'lsa, orkestrator sog'lom podlarni bekordan qayta ishga tushiradi.

**Internal** — gRPC, alohida port va listener (`proto/cc01/v1/access.proto`):

```
✅ AccessInternalService.AuthorizeTunnel   → ARCHITECTURE.md §3.4.3
   AccessInternalService.ReportUsage       usage batch (qabul qiladi, hali saqlamaydi)
```

**Internal listener hech qachon public interfeysga bind qilinmaydi.** Ikkala
listener `Program.cs` da oshkora sozlanadi:

| Listener | Protokol | Standart | Sozlash |
| --- | --- | --- | --- |
| Public | HTTP/1.1 + HTTP/2 | `0.0.0.0:5078` | `Public:Address`, `Public:Port` |
| Internal | h2c (gRPC) | `127.0.0.1:5081` | `Internal:Address`, `Internal:Port` |

Servis `RequireHost` bilan ichki portga qadalgan — public portga kelgan gRPC
so'rovi 404 oladi. Kubernetes'da qo'shimcha `NetworkPolicy` qo'yiladi.

> ⚠️ Endpointlar oshkora ko'rsatilgani uchun `ASPNETCORE_URLS` va
> `launchSettings.json` dagi `applicationUrl` **e'tiborga olinmaydi** — bu
> Kestrel'ning xatti-harakati, portlarni yuqoridagi kalitlardan o'zgartiring.

### 6.5 Xavfsizlik talablari (AP uchun)

| # | Talab |
| --- | --- |
| A-S1 | Parol: Argon2id yoki ASP.NET Identity PBKDF2 (≥ 100k iteratsiya); ochiq matn hech qayerda saqlanmaydi |
| A-S2 | Login rate limit: IP bo'yicha va hisob bo'yicha; 5 ta muvaffaqiyatsiz urinish → progressiv kechikish, 10 → vaqtinchalik lockout |
| A-S3 | API token faqat hash holida; solishtirish `CryptographicOperations.FixedTimeEquals` |
| A-S4 | Email tasdiqlanmaguncha tunnel ochib bo'lmaydi (`EMAIL_NOT_VERIFIED`) |
| A-S5 | `/internal/*` — mTLS majburiy; klient sertifikati CN allowlist bilan tekshiriladi |
| A-S6 | Subdomain deny-list (`www`, `api`, `admin`, `cp`, `edge`, `relay`, `stun`, `mail`, …) va `core-server/utils.go` dagi format qoidalari bilan **bir xil** validatsiya — ikkala tomonda ham |
| A-S7 | OAuth: `state` + PKCE (S256) majburiy; provider `sub` bo'yicha bog'lash, email bo'yicha emas (email o'zgarishi mumkin) |
| A-S8 | Audit: token yaratish/bekor qilish, subdomain o'zgarishi, tarif o'zgarishi, login — hammasi `AuditEvent`ga |
| A-S9 | PII: email va ism log'ga chiqmaydi; `Serilog` destructuring policy bilan maskalanadi |
| A-S10 | EF Core migratsiyalari deploy'dan **alohida** qadam; har birida rollback yo'li tekshirilgan |

**Amalda qo'shilgan, dastlab ro'yxatda bo'lmagan himoyalar:**

| # | Himoya | Sabab |
| --- | --- | --- |
| A-S11 | Login muvaffaqiyatsizligida email topilmasa ham parol hashi hisoblanadi (`IPasswordHasher.DummyHash`) | Aks holda javob vaqti hisob mavjudligini oshkor qiladi — timing orqali user enumeration |
| A-S12 | `INVALID_CREDENTIALS` — "email yo'q" va "parol xato" uchun bir xil kod va status | Xato matni orqali hisob mavjudligini aniqlashning oldini oladi |
| A-S13 | JWT'da `MapInboundClaims = false` | ASP.NET Core standart holda `sub` ni `ClaimTypes.NameIdentifier` ga o'zgartiradi; bu jimgina 500 xatoga olib kelgan edi |
| A-S14 | JWT imzolash va tekshirish parametrlari **ayni bir** `IOptions<JwtOptions>` dan oqadi | Konfiguratsiyani erta o'qish token bir kalit bilan imzolanib, boshqasi bilan tekshirilishiga olib keladi |
| A-S15 | Tarif kvotasi va tenant filtri har bir so'rovda (`TenantId` bo'yicha) | ID'ni bilgan begona tenant resursga tegib ketmasligi uchun |
| A-S16 | OAuth mavjud hisobga faqat **tasdiqlangan** email bilan bog'lanadi | Tasdiqlanmagan email bilan bog'lash — hisobni egallab olishning klassik yo'li (§6.6) |
| A-S17 | Provayder access tokeni saqlanmaydi (`SaveTokens = false`) | Bizga kerak emas; saqlash sizib chiqishda zararni kengaytiradi |
| A-S18 | "External" cookie bir marta o'qiladi va darhol o'chiriladi | Oqimning vaqtinchalik holati sessiyaga aylanib qolmasligi uchun |

### 6.6 OAuth (GitHub, Google)

Oqim uchta qadamdan iborat. State va PKCE'ni ASP.NET Core handleri o'zi
boshqaradi — qo'lda yozilgan kriptografiya yo'q:

```
GET /v1/auth/oauth/github
   → 302 https://github.com/login/oauth/authorize
        ?client_id=…&scope=read:user%20user:email&response_type=code
        &redirect_uri=…/v1/auth/oauth/github/callback
        &code_challenge=…&code_challenge_method=S256&state=…
     + Set-Cookie: .AspNetCore.Correlation.<…>   ← state shu bilan bog'lanadi

GET /v1/auth/oauth/github/callback?code=…&state=…
   → handler: state tekshiradi, code+code_verifier ni almashtiradi,
     profilni o'qiydi, "External" cookie'ga yozadi
   → 302 /v1/auth/oauth/complete

GET /v1/auth/oauth/complete
   → External cookie o'qiladi va DARHOL o'chiriladi
   → hisob topiladi/yaratiladi → JWT
```

| Qaror | Sabab |
| --- | --- |
| **PKCE (S256) ikkala provayderda ham** | GitHub 2025-dan beri qo'llab-quvvatlaydi (`plain` esa yo'q). Kod ushlab qolinsa ham `code_verifier`siz ishlatib bo'lmaydi |
| Bog'lash **provayder `sub`/`id`** bo'yicha, email bo'yicha emas | Email o'zgaradi, `sub` — yo'q. Emaili o'zgargan foydalanuvchi baribir o'z hisobiga tushadi |
| `read:user user:email` scope'lari | Profildagi email yopiq bo'lsa `/user` `null` qaytaradi; birlamchi tasdiqlangan manzil `/user/emails` dan olinadi |
| `SaveTokens = false` | Provayder access tokeni bizga kerak emas — uni saqlash ortiqcha xavf |
| "External" cookie — 10 daqiqa, bir marta o'qiladi | Bu foydalanuvchi sessiyasi emas, oqimning vaqtinchalik holati |
| Sozlanmagan provayder sxemasi ro'yxatga **olinmaydi** | Bo'sh `ClientId` bilan ro'yxatga olingan sxema har bir so'rovda `ArgumentException` tashlaydi — hatto `/livez` ham 500 qaytaradi |

**Hisobni egallab olishga qarshi qoida (eng muhim qism).** Provayder emaili
mavjud hisobga bog'lanishi mumkin, va aynan shu joyda klassik hujum bor:
tajovuzkor begona emailni o'z provayder profiliga yozib, o'sha email egasining
hisobiga kiradi. Shuning uchun:

| Holat | Xatti-harakat |
| --- | --- |
| `sub` allaqachon bog'langan | Kirish (email nimaligidan qat'i nazar) |
| `sub` yangi, email mavjud hisobniki, provayder emailni **tasdiqlagan** | Bog'lanadi va kiritiladi |
| `sub` yangi, email mavjud hisobniki, provayder emailni **tasdiqlamagan** | ❌ `OAUTH_EMAIL_UNVERIFIED` — bog'lanmaydi |
| `sub` yangi, email yangi, tasdiqlangan | Yangi tenant + parolsiz foydalanuvchi |
| `sub` yangi, email yangi, tasdiqlanmagan | ❌ `OAUTH_EMAIL_UNVERIFIED` |
| Email umuman yo'q | ❌ `OAUTH_EMAIL_MISSING` |

**Operatsion eslatma:** `state` Data Protection bilan shifrlanadi. Bir nechta
nusxa ishlaganda kalit halqasi umumiy bo'lishi shart (`PersistKeysToFileSystem`
umumiy jild yoki Redis), aks holda bir nusxa bergan `state`ni boshqasi
tekshira olmaydi va oqim "correlation failed" bilan uziladi. Faza 1 da
hal qilinadi.

**Sozlash:**

```
OAuth__Github__ClientId / OAuth__Github__ClientSecret
OAuth__Google__ClientId / OAuth__Google__ClientSecret
```

Provayder panelida ro'yxatdan o'tkaziladigan callback manzillari:
`https://<host>/v1/auth/oauth/github/callback` va `.../google/callback`.
Sirlar berilmasa o'sha provayder o'chiq qoladi va endpoint
`OAUTH_PROVIDER_NOT_CONFIGURED` qaytaradi — server baribir ishga tushadi.

**Hali sinalmagan qism:** callback'ning o'zi haqiqiy provayder kalitlarisiz
uchidan uchiga sinalmagan. Testlar bilan qoplangani: yo'naltirish
parametrlari (`state`, `code_challenge`, `S256`, scope, `redirect_uri`),
korrelyatsiya cookie'si, hisob bog'lash mantiqining barcha tarmoqlari va
sozlanmagan/noma'lum provayder holatlari. Provayder ilovasi yaratilgach
qo'lda tekshirish kerak.

### 6.7 Validatsiya kelishuvi (muhim)

Subdomain qoidalari hozir `core-server/utils.go` da (uzunlik 3–38, `^[a-z\d](?:[a-z\d]|-[a-z\d]){0,38}$`, deny-list). AP ham xuddi shu qoidani majburlashi kerak, aks holda foydalanuvchi dashboard'da band qilgan nom edge'da rad etiladi.

**Yechim:** qoidalar `proto/cc01/v1/access.proto` kommentariyasida yagona manba sifatida yoziladi va ikkala tomonda ham amalga oshiriladi; `test/contract/subdomain_test` bir xil 40+ kirish uchun ikkala implementatsiyani solishtiradi. Farq bo'lsa CI qizil.

> ⚠️ Hozirgi `validate()` xato xabari noto'g'ri: "length must be between 3 and 42" deydi, aslida yuqori chegara 38. Ko'chirishda tuzatiladi.

---

## 7. Sifat, xavfsizlik va operatsion talablar

### 7.1 Testlash strategiyasi

| Daraja | Qamrov maqsadi | Vositalar |
| --- | --- | --- |
| Unit | ≥ 80% (`internal/pkg`, `noise`, `ipv6` uchun ≥ 95%) | `go test`, `testify` |
| eBPF unit | Har bir stage uchun | `BPF_PROG_TEST_RUN` (sintetik paketlar) |
| Fuzz | Paket parser, protobuf decoder | `go-fuzz`, 24h nightly |
| Integration | NAT stsenariylari (full cone, restricted, symmetric, CGNAT) | Linux netns + `iptables` NAT simulyatsiyasi |
| E2E | 3 node + CP + relay + edge | Docker Compose, `test/e2e` |
| Performance | Throughput, pps, latency regressiya | `iperf3`, `pktgen`, `trex`; CI'da baseline'dan −5% → fail |
| Chaos | Relay o'ldirish, CP o'ldirish, paket yo'qotish 5% | `tc netem`, `pumba` |
| Contract | AP ↔ Edge: har bir xato kodi, subdomain validatsiya pariteti | `test/contract/`, ikkala tomonga qarshi |
| .NET unit/integration | `Application` qatlami ≥ 80%; API — `WebApplicationFactory` | `xunit`, `FluentAssertions`, `Testcontainers` (Postgres) |
| Security | Statik + dinamik | `gosec`, `govulncheck`, `trivy`, `dotnet list package --vulnerable`, tashqi pentest (GA'dan oldin) |

**Majburiy test stsenariylari (release blocker):**

1. Symmetric NAT ↔ Symmetric NAT → relay orqali ishlashi shart.
2. P2P yo'l uzilishi → 300 ms ichida relayga o'tish, TCP sessiya uzilmasligi.
3. CP o'chirilgan holatda mavjud trafik 12 soat davom etishi.
4. Spoofed inner src IPv6 → 100% drop.
5. 14.8 Mpps flood → XDP line-rate drop, CPU < 60%, legit trafik ta'sirlanmasligi.
6. eBPF map to'lganda (conntrack LRU evict) → sessiyalar uzilmasligi.
7. `cc01 down` → barcha marshrutlar/qoidalar tozalanishi (leak yo'q).
8. Daemon `SIGKILL` → keyingi start'da orphan resurslarni tozalash.
9. AP o'chirilgan holatda mavjud tunnellar ishlashda davom etishi; yangi tunnel kesh grace ichida qabul qilinishi.
10. Bekor qilingan token → keyingi `authorize` chaqirig'ida darhol rad etilishi (kesh TTL ≤ 60 s).
11. Boshqa foydalanuvchining subdomainini so'rash → `SUBDOMAIN_NOT_OWNED`, 100% holatda.
12. Bir xil 40+ subdomain kiritmasi uchun Go va .NET validatsiyasi bir xil natija berishi.

### 7.2 Xavfsizlik talablari (majburiy)

| # | Talab |
| --- | --- |
| S-1 | Private kalitlar hech qachon diskka aniq matnda yozilmaydi; TPM/Keychain bo'lsa u ishlatiladi |
| S-2 | Kalitlar `memguard` bilan `mlock` qilinadi, swap'ga tushmaydi |
| S-3 | Barcha CP aloqasi mTLS 1.3, sertifikat pinning bilan |
| S-4 | Cryptokey routing (`inner_src ∈ peer.allowed_ips`) — chetlab o'tib bo'lmaydi |
| S-5 | Daemon `CAP_NET_ADMIN`+`CAP_BPF` bilan ishlaydi, to'liq root emas (`AmbientCapabilities`) — ✅ `CAP_NET_ADMIN` uchun tekshirilgan |
| S-6 | systemd hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `RestrictSUIDSGID` — ✅ |
| S-7 | Supply chain: `go.sum` verify, SBOM (CycloneDX), Sigstore bilan imzolangan relizlar |
| S-8 | Reproducible builds (`-trimpath`, `CGO_ENABLED=0` mumkin bo'lganda) — ✅ `make package` |
| S-9 | Har bir reliz oldidan `govulncheck` — HIGH/CRITICAL bo'lsa bloklanadi |
| S-10 | Audit log tamper-evident (hash chain), ClickHouse'ga append-only |
| S-11 | AP ↔ Edge kanali mTLS; AP `/internal/*` listeneri public interfeysga bind qilinmaydi |
| S-12 | AP uchun qo'shimcha talablar §6.5 (A-S1…A-S10) da — ular ham majburiy |

### 7.3 CI/CD pipeline

```
PR ochilganda — o'zgargan yo'lga qarab (path filter):

  [har doim]  buf lint + buf breaking

  [go/**]     golangci-lint, clang-format
              → unit tests (Linux/macOS/Windows matritsa)
              → eBPF build + verifier check (kernel 5.15, 6.1, 6.8 matritsasi)
              → integration (netns NAT stsenariylari)
              → gosec + govulncheck
              → performance smoke (throughput regressiya)

  [access-server/**]
              → dotnet format --verify-no-changes
              → dotnet build -warnaserror
              → dotnet test (Testcontainers: Postgres + Redis)
              → EF migratsiya tekshiruvi: bo'sh bazaga up + down
              → dotnet list package --vulnerable --include-transitive

  [kontrakt]  test/contract — Go va .NET implementatsiyalarini solishtiradi

main'ga merge:
  → e2e (staging PoP, AP + edge + klient birga)
  → container build (multi-arch: amd64, arm64)
  → SBOM + cosign imzo
  → staging deploy (avtomatik)

tag v*:
  → canary (1 PoP, 5% trafik, 2 soat)
  → metrikalar tekshiruvi (error_rate, p95 latency, drop_rate)
  → progressive rollout (25% → 50% → 100%)
  → avtomatik rollback triggerlar: error_rate > 0.5% yoki p95 > baseline×1.3
```

### 7.4 Kod standartlari

- **Go:** `gofumpt`, `golangci-lint` (`errcheck`, `govet`, `staticcheck`, `revive`, `bodyclose`), `context.Context` har bir bloklanuvchi funksiyada birinchi argument, sentinel xatolar `errors.Is/As` bilan.
- **eBPF C:** `-Wall -Werror`, bounds check har bir pointer dereference'dan oldin, `__always_inline` helper'lar, verifier instruksiya soni CI'da o'lchanadi.
- **C#:** `.editorconfig` bilan yagona uslub, `dotnet format` CI'da; nullable reference types yoqilgan (`<Nullable>enable</Nullable>`), warning'lar xato sifatida; `async` metodlarda `CancellationToken` oxirgi parametr; domen mantiqi `Application` qatlamida, kontrollerlar yupqa.
- **Proto:** `buf breaking` — orqaga moslik buzilishi PR'ni bloklaydi; maydon raqamlari qayta ishlatilmaydi. `access.proto` Go va C# uchun ham generatsiya qilinadi.
- **Commit:** Conventional Commits (`feat:`, `fix:`, `perf:`, `refactor:`), har bir PR ≤ 400 qator o'zgarish (review sifati uchun).

---

## 8. Development Roadmap

### Faza 0 — Konsolidatsiya (6 hafta)

Maqsad: uchta mustaqil bo'lakni **bitta ishlaydigan mahsulotga** bog'lash — token bilan avtorizatsiya qilingan tunnel. Mesh va eBPF bu fazada boshlanmaydi.

**0.A — Skelet va kontrakt**

| Deliverable | Acceptance criteria | Holat |
| --- | --- | --- |
| `go.work` + `Makefile` | `make build` `core-server` va `cli-client`ni quradi | ✅ |
| `proto/cc01/v1/{tunnel,access}.proto` + `buf` | `buf lint` o'tadi; `make proto` Go kodini generatsiya qiladi | ✅ |
| `events` paketi `gob` → protobuf | Eski va yangi klient bir vaqtda ishlamaydi — preambula (`"CC01"` + versiya) qo'shiladi, eski format rad etiladi | ✅ |
| `deploy/docker-compose.dev.yml` | `make dev-up` → postgres + redis, ulanish tekshirilgan | ✅ |
| CI: path-filter bilan Go va .NET yo'llari | Ikkala yo'l ham yashil | ✅ yozildi (hali push qilinmagan) |

**0.B — Access Server ishga tushishi**

| Deliverable | Acceptance criteria | Holat |
| --- | --- | --- |
| §6.1 A-1…A-8 tuzatishlari | Shablon qoldiqlari yo'q; qatlam referenslari to'g'ri; `Insfrastructure` → `Infrastructure` | ✅ |
| Domen modeli (`Tenant` ildizda) | `Tenant` / `User` / `ApiToken` / `Subdomain` + enumlar | ✅ |
| EF Core + PostgreSQL + birinchi migratsiya | `make db-verify`: up → down → up ishlaydi; indekslar §6.2 ga mos | ✅ |
| Api ↔ baza ulanishi + health endpointlari | `/readyz` baza yiqilganda 503, tiklanganda 200 — tekshirilgan | ✅ |
| Auth: register, login, email tasdiqlash | Integration testlar yashil | ✅ |
| API token: yaratish, ro'yxat, bekor qilish | Sir bir marta ko'rsatiladi; bazada faqat hash; bekor qilish darhol kuchga kiradi | ✅ |
| Subdomain egaligi (rezervatsiya) | Band nom boshqa tenantga berilmaydi; validatsiya §6.7 ga mos | ✅ |
| OAuth: GitHub, Google (PKCE + state) | Yo'naltirish parametrlari va bog'lash mantiqi testlar bilan; callback qo'lda tekshiriladi | ✅ (§6.6) |

83 ta test (unit + integration + HTTP) yashil. Testlash bo'yicha ikkita qaror:

- **`Testcontainers` ishlatilmadi.** Bu mashinada docker konteksti masofaviy serverga qaratilgan bo'lishi mumkin va Testcontainers uni jimgina ishlatib yuborardi. O'rniga oshkora ulanish satri: `CC01_TEST_DB`. Har bir yugurish o'ziga alohida baza yaratadi va oxirida o'chiradi.
- **HTTP darajasidagi testlar majburiy.** Handler'ni to'g'ridan-to'g'ri chaqiradigan testlar routing, JWT claim'lari va xato → status xaritasini ko'rmaydi. Amalda aynan shu qatlamda ikkita xato topildi (§6.5 A-S13, A-S14) — ikkalasi ham handler testlaridan bemalol o'tib ketgan edi.

**0.C — Bog'lash**

| Deliverable | Acceptance criteria | Holat |
| --- | --- | --- |
| `AccessInternalService.AuthorizeTunnel` | Xato kodlarining har biri uchun test | ✅ |
| `core-server` tunnel so'rovida tokenni tekshiradi | Tokensiz so'rov rad etiladi; subdomain egasi bo'lmagan foydalanuvchi rad etiladi | ✅ |
| Avtorizatsiya keshi + fail-static grace | AP o'chirilganda mavjud tunnellar ishlaydi (§7.1 majburiy stsenariy 9) | ✅ |
| Kvota majburlash: `max_conns_per_tunnel` | Hozirgi qattiq `24` o'rniga tarifdan keladigan qiymat | ✅ |
| Avtorizatsiya deny-by-default | `CC01_ACCESS_ADDR` sozlanmagan bo'lsa server ishga tushmaydi | ✅ |
| **Faza 0 demo** | Ro'yxatdan o'tish → token olish → tunnel ochish → brauzerdan ochilishi | ✅ |
| mTLS: AP ↔ Edge | Klient sertifikati CN allowlist bilan | ⏳ Faza 1 |
| `ReportUsage` + `UsageRecord` | Bayt/ulanish hisobi dashboard'da ko'rinadi | ⏳ RPC bor, saqlash Faza 1 |
| `test/contract/` — validatsiya pariteti | Go va .NET 40+ kirishda bir xil natija | ⏳ ikkala tomonda testlar bor, taqqoslash yo'q |

**Faza 0 demo qanday tekshirildi** (qo'lda, uchidan uchiga):

```
1. register → verify-email → login → POST /v1/tokens   → cc01_live_…
2. core-server: CC01_ACCESS_ADDR=127.0.0.1:5081
3. cc01 -subdomain myapp -token cc01_live_…            → tunnel ochildi
4. curl -H 'Host: myapp.cc01.test' :8080               → 200, lokal servis javobi

   tokensiz / yaroqsiz token                           → TOKEN_INVALID
   boshqa hisob 'myapp' ni so'raydi                    → SUBDOMAIN_NOT_OWNED
   access-server o'chirilgan, mavjud tunnellar         → 200 (fail-static)
   access-server o'chirilgan, yangi tunnel, kesh sovuq → SERVICE_UNAVAILABLE
```

**Bu fazada ataylab qilinmaydigan ishlar:** TUN, Noise, ICE, relay, eBPF, IPv6, BGP. Ular Faza 1–4 da; hozirgi maqsad — oxirigacha ishlaydigan tor bir yo'l.

### Faza 1 — MVP Mesh (8 hafta) 🎯 **MVP**

Faza 0 dan farqli — bu yerda haqiqiy overlay boshlanadi. Foundation ishlari (TUN, Noise) shu fazaga ko'chirildi.

| Deliverable | Acceptance criteria | Holat |
| --- | --- | --- |
| Noise IK handshake | Ikki daemon kalit almashadi, shifrlangan echo ishlaydi | ✅ `daemon/noise` |
| Sessiya: rekey, replay oynasi, nonce | Takroriy paket rad etiladi; nonce takrorlanmaydi | ✅ |
| TUN yaratish (Linux) + batch I/O | ICMPv6 aylanishi TUN orqali ishlaydi | ✅ `daemon/tun` |
| Marshrut: ajratilgan jadval + policy qoidalari | `Close()` dan keyin 0 orphan marshrut | ✅ |
| Crypto router (cryptokey routing) | `inner_src ∈ peer.allowed_ips` — 100% drop | ✅ `daemon/router` |
| UDP transport (batch I/O) | `recvmmsg`/`sendmmsg` Linux'da | ✅ `daemon/conn` |
| Datapath engine (goroutine'lar, handshake, keepalive, rekey) | Ikki node o'rtasida shifrlangan `ping6` | ✅ `daemon/engine` |
| Control Plane: register, NetworkMap | Tenant izolyatsiyasi, delta sync | ✅ `control/registry` + `control/server` |
| `cc01d` CP rejimi | Peerlar qo'lda emas, CP dan avtomatik | ✅ `daemon/control` |
| Control Plane: Raft KV | 3 replika, leader failover < 5 s | ⏳ `Store` interfeysi tayyor |
| IPAM: `/128` allocate/renew/release | 1000 node, double-allocation 0 | ✅ `control/ipam` |
| STUN: public manzilni aniqlash | NAT ortidagi node ikki tomonlama ulanadi | ✅ `daemon/stun` + `control/stunserver` |
| UDP hole punching (cone NAT) | Ikkala tomon ham relaydan `direct-active` ga o'tadi | ✅ `make punch-demo` |
| UDP hole punching (symmetric NAT) | Birthday-paradox punching | ⏳ |
| Relay servisi + fallback | Symmetric NAT'da ulanish; relay yukni ocha olmaydi | ✅ `make relay-demo` |
| Yo'l tanlash + avtomatik fallback | Relay-first, P2P-upgrade; degradatsiyada relayga qaytish | ✅ `daemon/path` |
| Marshrut sinxronizatsiyasi (reconciliation) | Peer ketganda marshruti ham ketadi; `Close()` dan keyin 0 orphan | ✅ `daemon/route` |
| CLI ↔ demon IPC (UNIX soket, gRPC) | `SO_PEERCRED`, `0660`, exit kodlari §5.2 | ✅ `daemon/ipc` |
| CLI: `status`, `peer list`, `doctor` | Ishlab turgan mesh'da yo'l holati ko'rinadi | ✅ `make cp-demo` |
| CLI: `up`, `down` (demon hayot sikli) | `down` → 0 marshrut, `up` → o'sha manzil qaytadi | ✅ `daemon/session` |
| Linux paketlar (deb/rpm) + systemd unit | Toza konteynerda o'rnatiladi, `make package-verify` | ✅ `deploy/packaging` |
| AP: `Plan`, `Subscription`, kvota modeli | Tarif o'zgarishi 60 s ichida edge'da kuchga kiradi | ⏳ |
| **MVP demo** | 3 shahar, 3 node, o'zaro ping < 50 ms, public IPv6 internetdan erishiladi | ⏳ |

**Datapath bo'yicha o'lchangan natija** (Apple M5, ChaCha20-Poly1305):

| Ko'rsatkich | O'lchov | NFR maqsadi |
| --- | --- | --- |
| Seal + Open (1280 bayt) | 2.4 µs, 535 MB/s | — |
| To'liq datapath (marshrutlash + kripto + cryptokey check) | 2.4 µs, 536 MB/s | — |
| Bir yo'nalishda | ~8 Gbps/yadro | ≥ 2.5 Gbps/yadro ✅ |
| `allowed_ips` LPM qidiruvi (500 peer) | 46 ns, **0 ajratma** | — |
| Replay oynasi `Accept` | 6 ns | — |
| Ajratmalar | 4 alloc, 2720 B/paket | ⚠️ line-rate'da GC bosimi; bufer qayta ishlatish Faza 6 (`fastpath`) |

Marshrutlash va xavfsizlik tekshiruvi kripto ustiga **o'lchanadigan yuk qo'shmadi** —
qidiruv 46 ns, shifrlash esa 2.4 µs.

**IPAM unumdorligi** (`control/ipam`). Dastlabki implementatsiya har bir
taqsimlashda butun holatni nusxalardi; bu 100 000 tenant maqsadida (§8)
ishlamas edi:

| Bosqich | Vaqt | Xotira | Ajratmalar |
| --- | --- | --- | --- |
| Butun holatni nusxalash | 1.47 ms | 3.1 MB | 5121 |
| `ByParent` indeksi + nusxalashsiz | 239 µs | 1.7 KB | 14 |
| Tozalashni faqat pool to'lganda | **3.3 µs** | 1.8 KB | 14 |

Ikkita qaror shundan kelib chiqdi:

1. **`Store.Update` xatoda avtomatik orqaga qaytarmaydi.** Butun holatni
   nusxalash `O(N)`. Buning o'rniga kelishuv: `fn` avval tekshiradi,
   keyin o'zgartiradi. Raft'da ham xuddi shunday — `Apply` allaqachon
   commit qilingan buyruqni qo'llaydi. Sticky tiklashdagi yagona
   istisno oshkora qo'lda qaytariladi.
2. **Muddati o'tgan ijaralarni tozalash faqat pool to'lgandek
   ko'ringanda ishlaydi**, har bir taqsimlashda emas. Odatiy yo'l
   `O(1)`, kamdan-kam uchraydigan yo'l `O(N)` to'laydi.

**Delta sync o'lchovi** (`control/registry`, 500 peerli tenant). Hujjatdagi
bashorat (§3.1.2: "to'liq map ~200 KB, delta odatda < 2 KB") tasdiqlandi:

| So'rov | Vaqt | Xotira |
| --- | --- | --- |
| To'liq map (500 peer) | 99 µs | 159 KB |
| Delta (o'zgarishsiz) | **139 ns** | **384 B** |

Uchta xatti-harakat alohida qo'riqlanadi:

- **Heartbeat versiyani oshirmaydi**, agar endpointlar o'zgarmagan bo'lsa.
  Aks holda har 30 sekundda butun tenantga delta yuborilardi.
- **Bir nodening ketma-ket o'zgarishlari deltada bir marta** ko'rinadi —
  klientga oraliq holatlar kerak emas, faqat oxirgisi.
- **Jurnal kesilganda to'liq map** qaytariladi. Juda orqada qolgan klient
  o'zgarishlarni jimgina o'tkazib yubormasligi kerak.

**Relay orqali ulanish** (`make relay-demo`). Ikkita node, **har biri
o'z NAT'i ortida** — ular bir-birini to'g'ridan-to'g'ri ko'ra olmaydi:

```
net-public  172.34.0.0/24   cp + stun + relay, gw-a, gw-b
net-a       172.34.1.0/24   node-1  → gw-a (172.34.0.2)
net-b       172.34.2.0/24   node-2  → gw-b (172.34.0.3)

node-1: "public manzil aniqlandi" 172.34.0.2:51820
node-1: "relayga ulandi" relay-1
node-2: "relayga ulandi" relay-1

node-1 → node-2:  0% yo'qotish, ~1.4 ms
node-2 → node-1:  0% yo'qotish, ~1.1 ms

sessiya: via=relay
```

node-1 node-2 ning NAT manziliga to'g'ridan-to'g'ri yubora olmaydi:
gw-b da mos conntrack yozuvi yo'q. Yagona yo'l — relay, va datapath
unga **avtomatik** o'tadi.

CP relay ro'yxatini NetworkMap orqali tarqatadi (`relays[]`). Ro'yxat
har bir javobda to'liq yuboriladi — u kichik va kamdan-kam o'zgaradi,
ya'ni delta hisoblash ortiqcha murakkablik bo'lardi.

**Yo'l tanlash** (`daemon/path`) — ADR-005: *relay-first, P2P-upgrade*.
Ulanish darhol relaydan boshlanadi, to'g'ridan-to'g'ri yo'l esa fon
rejimida sinaladi va tasdiqlangach unga o'tiladi.

`§6.2` holat mashinasi to'liq amalga oshirilgan:

```
discovering → relay-active → probing → direct-active
                                 ↑          ↓ 3 javobsizlik
                                 └──────  degraded
                                      5 javobsizlik
```

`§6.3` taymerlari:

| Chegara | Qiymat | Nima uchun |
| --- | --- | --- |
| Tasdiqlangan yo'lni o'lchash | 5 s | Sifatni kuzatish |
| Tasdiqlanmagan yo'lni sinash | **500 ms** | Quyida |
| Javobsizlikdan keyin | 250 ms | Uzilishni tez aniqlash |
| Degradatsiya | 3 javobsizlik (750 ms) | Hali direct'da qoladi |
| Relayga qaytish | 5 javobsizlik (1250 ms) | Hot switch |
| Upgrade sharti | 15% tez, 3 o'lchov | Flapping'ning oldini olish |

**Dastlabki probe davri ataylab tezroq.** 5 soniyalik davrda tasdiqlash
`3 × 5 = 15` soniya olardi — ya'ni foydalanuvchi shuncha vaqt relayda
o'tirardi. Bu ADR-005 ning maqsadiga zid: relay **boshlanish** uchun,
doimiy yo'l uchun emas. O'lchov: tasdiqlash **10.6 s → 1.53 s**.

**Disco ping/pong** uchun yangi paket turi qo'shildi: `0x07`. Asl
ro'yxat `0x01–0x06` edi; keepalive javob kutmagani uchun kechikishni
o'lchay olmaydi. Xabar 9 bayt: tur + nonce. Vaqt tamg'asi yuborilmaydi —
RTT ni jo'natuvchi o'zi o'lchaydi, ya'ni soatlar mos kelishi shart emas.

**Relay orqali kelgan paketda endpoint O'RGANILMAYDI.** Manba manzili
relayniki, peerniki emas; uni yozib qo'yish to'g'ridan-to'g'ri yo'lni
buzardi. `acceptTransport` va handshake ishlovchilari `learnEndpoint`
bayrog'ini oladi.

**Relay** (`daemon/relay`). Ikki qatlamli shifrlash bilan:

```
[ node ↔ relay Noise sessiyasi           ]  ← relay ochadi
    [ dst_node_id | peer↔peer shifr matn ]  ← relay OCHA OLMAYDI
```

Tashqi qatlam metadata'ni himoyalaydi: tarmoqni kuzatayotgan tomon kim
kim bilan gaplashayotganini ko'rmaydi. Ichki qatlam esa relayning o'zidan
himoyalaydi — u faqat `node_id` ni ko'radi (`ARCHITECTURE.md` §5.1 dagi
kompromis radiusi jadvali aynan shuni va'da qiladi).

Ikkita xususiyat alohida test bilan qo'riqlanadi:

| Xususiyat | Nima uchun |
| --- | --- |
| Relay ichki yukni ocha olmaydi | Uning butun ma'nosi shu; test ochiq matn uzatilgan baytlarda yo'qligini tekshiradi |
| Jo'natuvchini soxtalashtirib bo'lmaydi | `node_id` klient yuborgan qiymatdan emas, **autentifikatsiya qilingan sessiyadan** olinadi |

`node_id` relay tomonidan Noise IK handshake'ida bilib olingan public
kalitdan hisoblanadi — ya'ni boshqa nodening nomidan ro'yxatdan o'tish
imkonsiz.

**NAT ortidan ulanish** (`make nat-demo`). Docker'da MASQUERADE qiluvchi
shlyuz orqali haqiqiy NAT simulyatsiya qilinadi:

```
net-public   172.33.0.0/24   cc01-cp, node-2, gw:eth0
net-private  172.33.1.0/24   gw:eth1, node-1   ← default route → gw

node-1: "public manzil aniqlandi" endpoint=172.33.0.2:51820   ← STUN
node-2: "peer qo'shildi" node-1 endpoint=172.33.0.2:51820     ← CP orqali

node-1 → node-2:  0% yo'qotish
node-2 → node-1:  0% yo'qotish   ← NAT ICHIGA kirish
```

Ikkinchi yo'nalish muhimroq: u faqat STUN node-1 ning tashqi manzilini
topgani va CP uni node-2 ga yetkazgani uchun ishlaydi. STUN'siz node-1
o'zining `172.33.1.11` manzilini e'lon qilardi — unga tashqaridan
erishib bo'lmaydi.

**Ikkita qoida shu ishdan chiqdi:**

1. **STUN datapath bilan AYNI soketdan** yuborilishi shart. NAT
   bog'lanishi soketga bog'langan; boshqa soketdan so'ralgan manzil
   overlay uchun yaroqsiz bo'ladi.
2. **Engine ishga tushishidan oldingi o'qish sinxron bo'lishi shart.**
   Dastlabki versiya alohida goroutine'da o'qirdi va u `Receive` da
   bloklangan holda qolib ketardi — keyinchalik u datapath'ning
   birinchi paketini (handshake initiation) o'g'irlab, mesh'ni
   **jimgina** ishlamaydigan qilib qo'yardi. `stun.DiscoverOnce`
   o'qishni chaqiruvchi goroutine'da bajaradi va regressiya testi
   buni qo'riqlaydi.

**Paketlarni ajratish aniq, ehtimolli emas.** STUN javoblari o'sha
soketga keladi va ular `magic cookie` (0x2112A442) bo'yicha ajratiladi.
cc01 sarlavhasida o'sha o'rinda `receiver_index` turadi — shuning uchun
`noise.randomIndex()` mos keladigan yagona qiymatni (`0x42A41221`)
ataylab chetlab o'tadi.

**Avtomatik mesh** (`make cp-demo`): Control Plane va uchta node, hech
qanday qo'lda peer konfiguratsiyasisiz. Har bir node faqat CP manzilini
biladi:

```
cc01-cp  -tenant-net fd00:cc01:c0de::/64
cc01d    -cp 172.32.88.5:8443            ← peer flaglari YO'Q

CP:      node-1 → fd00:cc01:c0de:0:59c4:775:545c:3224/128
         node-2 → fd00:cc01:c0de:0:c6ad:d1c:161d:9e3b/128
         node-3 → fd00:cc01:c0de:0:987d:e17:dc4e:49b2/128

node-1:  "peer qo'shildi" node-2 endpoint=172.32.88.12:51820
         "peer qo'shildi" node-3 endpoint=172.32.88.13:51820

ping6:   1→2, 1→3, 3→2 — hammasi 0% yo'qotish
```

Ketma-ketlik muhim: UDP soketi ochiladi (endpoint uchun port kerak) →
CP da ro'yxatdan o'tiladi (manzil shu yerda beriladi) → TUN yaratiladi →
engine ishga tushadi → CP stream'i peerlarni to'ldiradi.

**Ikki node, statik konfiguratsiya bilan** (`make mesh-demo`):

```
$ ping -6 -c 4 fd00:cc01:beef::2
64 bytes from fd00:cc01:beef::2: icmp_seq=1 ttl=64 time=3.97 ms
64 bytes from fd00:cc01:beef::2: icmp_seq=2 ttl=64 time=0.688 ms
...
4 packets transmitted, 4 received, 0% packet loss
```

Birinchi paket sekinroq — u handshake tugashini kutadi va navbatda
turadi; keyingilari o'rnatilgan sessiyadan foydalanadi.

**Cryptokey routing** (`ARCHITECTURE.md` §4.2) — `daemon/router` ning asosiy
vazifasi. `allowed_ips` ikki ish bajaradi:

| Yo'nalish | Vazifa |
| --- | --- |
| Chiqish | Marshrutlash jadvali: qaysi manzillar shu peerga ketadi |
| Kirish | **Ruxsat ro'yxati**: shu peer qaysi manzillardan yoza oladi |

Ikkinchisisiz Noise sessiyasi paketning shu peerdan kelganini isbotlaydi,
lekin **ichidagi manba manzilini emas**. Ya'ni tarmoqqa qonuniy ulangan
har qanday node boshqasining nomidan gaplasha olardi. Test aynan shu
stsenariyni tekshiradi: qonuniy peer (haqiqiy kalitlar, muvaffaqiyatli
handshake) begona manzildan yozmoqchi bo'ladi va rad etiladi.

### Faza 2 — eBPF Security Layer (6 hafta)

| Deliverable | Acceptance criteria |
| --- | --- |
| `xdp_filter` Stage 0–5 to'liq | `BPF_PROG_TEST_RUN` testlari 100% o'tadi |
| Policy compiler (ACL → LPM trie) | 10k qoida < 500 ms kompilyatsiya |
| `cc01 firewall` buyruqlari + dry-run | `firewall test` to'g'ri qoidani ko'rsatadi |
| Ring buffer event pipeline | 100k event/s yo'qotishsiz |
| Anti-DDoS: rate limit + SYN cookie | 14.8 Mpps flood, legit trafik SLO ichida |
| Mikrosegmentatsiya (tag-based) | Lateral movement testi bloklanadi |

### Faza 3 — Tunneling / ngrok parity (6 hafta)

| Deliverable | Acceptance criteria |
| --- | --- |
| Edge ingress: SNI router + TLS terminatsiya | 50k concurrent tunnel/node |
| ACME avtomatizatsiyasi (wildcard + on-demand) | Sertifikat < 30 s, avto-renew |
| `tunnel http/tcp/udp/tls` | ngrok bilan funksional paritet (asosiy stsenariylar) |
| QUIC transport + stream mux | HTTP p95 overhead < 8 ms |
| Traffic inspector (`:4040`) | So'rov/javob real vaqtda ko'rinadi |
| Custom domain + basic/OAuth auth | Dokumentatsiya bilan |
| AP: `CustomDomain` + TXT verifikatsiya oqimi | Domen tasdiqlangach ACME avtomatik ishga tushadi |
| AP: billing integratsiyasi + usage hisob-kitobi | Oylik hisob usage bilan mos keladi |

### Faza 4 — Edge Transit & TasIX (5 hafta)

| Deliverable | Acceptance criteria |
| --- | --- |
| `tas1` PoP: bare metal, BGP, TasIX peering | O'zbekistonlik klientdan RTT p95 ≤ 5 ms |
| Anycast VIP + GeoDNS | Foydalanuvchi doim eng yaqin PoP'ga tushadi |
| GUA prefiks e'loni (`/48`) | Internetdan node IPv6'siga to'g'ridan-to'g'ri erishish |
| Health-based BGP withdrawal + BFD | PoP failover < 15 s |
| 2-chi va 3-chi PoP (`fra1`, `sin1`) | Multi-region relay tanlash to'g'ri ishlaydi |

### Faza 5 — Multi-platform & Scale (6 hafta)

| Deliverable | Acceptance criteria |
| --- | --- |
| macOS, Windows klientlar (GUI bilan) | Feature parity (eBPF'siz fallback filtr) |
| iOS/Android (NetworkExtension / VpnService) | App Store / Play Store'da |
| Web dashboard | Tenant, node, policy, tunnel boshqaruvi; AP `/v1/*` API ustida |
| Delta sync + lazy mesh | 10 000 node/tenant, map push < 2 KB |
| Observability to'liq (Grafana dashboardlar) | SLO alertlari ishlaydi |
| SOC2-ready audit log | Tashqi auditor tekshiruvidan o'tish |

### Faza 6 — Advanced (davomiy)

| Deliverable |
| --- |
| Rust `fastpath` (AF_XDP zero-copy) — 40 Gbps/node maqsad |
| WASM edge compute filtrlari |
| Post-quantum handshake (X25519 + ML-KEM-768) |
| Self-hosted / on-premise Control Plane |
| SD-WAN: multipath, FEC, kanal agregatsiyasi |

### 8.1 Umumiy taymlayn

```
Oy:      1───2───3───4───5───6───7───8───9───10──11──12──13
Faza 0:  ██████                              ← 🎯 Tokenli tunnel demo (oy 1.5)
Faza 1:        ████████                      ← 🎯 MVP Mesh (oy 3.5)
Faza 2:                ██████
Faza 3:                      ██████          ← 🎯 Public Beta (oy 8.5)
Faza 4:                            █████
Faza 5:                                ██████ ← 🎯 GA (oy 13)
Faza 6:                                      ═══════►
```

### 8.2 Jamoa tarkibi (minimal)

| Rol | Soni | Asosiy mas'uliyat |
| --- | --- | --- |
| Systems/Network Engineer (Go) | 2 | Klient daemon, mesh, ICE/relay |
| Kernel/eBPF Engineer | 1 | XDP/TC dasturlari, fastpath |
| Backend Engineer (Go) | 2 | Control Plane, IPAM, API |
| Edge/Infra Engineer | 1 | PoP, BGP, TasIX, Terraform |
| SRE | 1 | CI/CD, observability, on-call |
| Backend Engineer (.NET) | 1 | `access-server`: auth, token, tarif, billing |
| Frontend | 1 | Dashboard, CLI UX |
| Security Engineer | 0.5 | Threat model, audit, pentest koordinatsiyasi |

---

## 9. Definition of Done

Har bir feature quyidagilar bajarilgandan keyin "done" hisoblanadi:

- [ ] Kod review ≥ 1 approve (xavfsizlikka tegsa — Security engineer approve)
- [ ] Unit testlar yozilgan, qamrov pasaymagan
- [ ] Integration test stsenariysi qo'shilgan (agar tarmoq xatti-harakatiga tegsa)
- [ ] eBPF o'zgarishi bo'lsa — 3 ta kernel versiyasida verifier o'tgan
- [ ] AP ↔ Edge kontraktiga tegsa — `proto/` yangilangan, `buf breaking` o'tgan, kontrakt testi qo'shilgan
- [ ] EF Core migratsiyasi bo'lsa — `up` va `down` bo'sh bazada tekshirilgan
- [ ] Metrika va log qo'shilgan (kuzatilmaydigan feature — tugallanmagan feature)
- [ ] Dokumentatsiya yangilangan (`--help`, `docs/`, ADR agar arxitektura qarori bo'lsa)
- [ ] Performance regressiya yo'q (CI baseline)
- [ ] Rollback yo'li aniqlangan (feature flag yoki config toggle)
- [ ] Runbook yozilgan (operatsion ta'sirga ega bo'lsa)

---

## 10. Ochiq savollar (implementatsiyadan oldin hal qilinishi kerak)

| # | Savol | Mas'ul | Muddat |
| --- | --- | --- | --- |
| Q-1 | IPv6 prefiks: RIPE'dan to'g'ridan-to'g'ri `/32` olinadimi yoki upstream ISP'dan `/40`? | Network Lead | Faza 1 boshi |
| Q-2 | TasIX peering shartlari, ASN ro'yxatdan o'tkazish muddati | Infra Lead | Faza 1 |
| Q-3 | `edge-terminate` rejimi uchun huquqiy/compliance talablar (trafik terminatsiyasi) | Legal + Security | Faza 3 boshi |
| Q-4 | Free tarif limitlari (relay bandwidth, tunnel soni) — abuse'ni oldini olish | Product | Faza 3 |
| Q-5 | Mobil platformalarda xotira limiti ostida necha peer? | Mobile Eng | Faza 5 |
| Q-6 | Self-hosted CP litsenziyasi (BSL / AGPL / commercial) | Leadership | Faza 4 |
| Q-7 | AP bazasi: o'z-o'zidan boshqariladigan PostgreSQL, boshqariladigan (Neon/RDS) yoki CP bilan bir klaster? | Infra Lead | Faza 0.B |
| ~~Q-8~~ | ~~Tenant modeli~~ → **HAL QILINDI (2026-08-20):** `Tenant` birinchi darajali entity, `User` unga a'zo. Sabab quyida. | — | ✅ |
| Q-9 | Free tarifda subdomain muddatli (`ReservedUntil`) bo'ladimi yoki doimiymi? Squatting'ni oldini olish | Product | Faza 0.C |
| Q-10 | Billing provayderi (Payme/Click mahalliy, Stripe xalqaro) va soliq talablari | Product + Legal | Faza 3 |
| Q-11 | AP va CP bir xil `tenant_id` makonini qanday bo'lishadi — AP manba bo'ladimi yoki `cc01-idp`? | Backend Lead | Faza 1 |

---

**Q-8 qarori va sababi:** javob aslida arxitekturaning o'zida turgan edi. `ARCHITECTURE.md` glossariysi tenantni izolyatsiya chegarasi deb ta'riflaydi, `Grant` javobi `tenant_id` qaytaradi va kvotalar tenant bo'yicha hisoblanadi. `User` = tenant qilish bu qarorlarga zid bo'lardi. Shuning uchun `Tenant` birinchi darajali entity; ro'yxatdan o'tishda shaxsiy tenant avtomatik yaratiladi. Jamoa qo'shish keyinchalik faqat a'zolik jadvalini talab qiladi — ma'lumot migratsiyasini emas.

Bu qarorning narxi hozir deyarli nol: bitta qo'shimcha jadval va har bir so'rovda `TenantId` filtri.

---

*Hujjat oxiri. Arxitektura konteksti uchun `ARCHITECTURE.md`ga, Account Plane qarori uchun `adr/ADR-009.md`ga qarang.*
