using AccessServer.Domain.Enums;

namespace AccessServer.Application.Subdomains;

/// <param name="MaxConnectionsPerTunnel">
/// core-server'dagi qattiq yozilgan 24 ning o'rnini bosadi (Faza 0.C).
/// </param>
public readonly record struct PlanLimits(
    int MaxSubdomains,
    int MaxTunnels,
    int MaxConnectionsPerTunnel,
    long BandwidthBps);

/// <summary>
/// Faza 0 da tarif limitlari kod ichida. To'liq `Plan`/`Subscription`
/// entity'lari Faza 1 da (DEV_SPEC §8) — o'shanda bu jadval bazadan o'qiladi
/// va bu sinf faqat zaxira qiymat sifatida qoladi.
/// </summary>
public static class PlanCatalog
{
    public static PlanLimits For(PlanCode plan) => plan switch
    {
        PlanCode.Free => new PlanLimits(
            MaxSubdomains: 1,
            MaxTunnels: 1,
            MaxConnectionsPerTunnel: 24,
            BandwidthBps: 100_000_000),

        PlanCode.Pro => new PlanLimits(
            MaxSubdomains: 10,
            MaxTunnels: 10,
            MaxConnectionsPerTunnel: 128,
            BandwidthBps: 1_000_000_000),

        PlanCode.Enterprise => new PlanLimits(
            MaxSubdomains: 100,
            MaxTunnels: 100,
            MaxConnectionsPerTunnel: 1024,
            BandwidthBps: 0),  // 0 = cheklanmagan

        _ => For(PlanCode.Free),
    };
}
