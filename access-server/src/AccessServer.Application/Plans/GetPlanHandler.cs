using AccessServer.Application.Abstractions;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Plans;

public sealed record PlanSubscriptionView(
    SubscriptionStatus Status,
    DateTimeOffset PeriodStart,
    DateTimeOffset? PeriodEnd);

public sealed record PlanLimitsView(
    int MaxSubdomains,
    int MaxTunnels,
    int MaxConnsPerTunnel,
    long BandwidthBps);

public sealed record PlanUsageView(int Subdomains);

/// <param name="Plan">AMALDAGI tarif (muddat va holat hisobga olingan), saqlangani emas.</param>
/// <param name="Subscription">Saqlangan obuna qatori; yo'q bo'lsa null.</param>
public sealed record PlanView(
    PlanCode Plan,
    EffectivePlanSource Source,
    PlanSubscriptionView? Subscription,
    PlanLimitsView Limits,
    PlanUsageView Usage);

/// <summary>
/// Dashboard uchun: amaldagi tarif, limitlar va joriy foydalanish.
/// Limitlar edge oladigan manbadan — EffectivePlanResolver'dan — o'qiladi,
/// shuning uchun ikkalasi hech qachon farq qilmaydi.
/// </summary>
public sealed class GetPlanHandler(IAccessDbContext db, EffectivePlanResolver planResolver)
{
    public async Task<PlanView> HandleAsync(int tenantId, CancellationToken cancellationToken = default)
    {
        var effective = await planResolver.ResolveAsync(tenantId, cancellationToken);

        var subscription = await db.Subscriptions
            .AsNoTracking()
            .Where(s => s.TenantId == tenantId)
            .Select(s => new PlanSubscriptionView(s.Status, s.PeriodStart, s.PeriodEnd))
            .SingleOrDefaultAsync(cancellationToken);

        // Released nomlar kvotaga kirmaydi (ReserveSubdomainHandler bilan bir xil).
        var subdomains = await db.Subdomains
            .CountAsync(s => s.TenantId == tenantId
                             && s.Status != SubdomainStatus.Released, cancellationToken);

        var limits = effective.Limits;

        return new PlanView(
            effective.Code,
            effective.Source,
            subscription,
            new PlanLimitsView(
                limits.MaxSubdomains,
                limits.MaxTunnels,
                limits.MaxConnectionsPerTunnel,
                limits.BandwidthBps),
            new PlanUsageView(subdomains));
    }
}
