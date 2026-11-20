using AccessServer.Application.Abstractions;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Plans;

/// <summary>Amaldagi limitlar qayerdan olingani.</summary>
public enum EffectivePlanSource
{
    /// <summary>Aktiv va muddati o'tmagan obuna.</summary>
    Subscription = 0,

    /// <summary>Obuna qatori yo'q — Free.</summary>
    NoSubscription = 1,

    /// <summary>Obuna muddati o'tgan — Free.</summary>
    Expired = 2,

    /// <summary>Obuna bekor qilingan — Free.</summary>
    Canceled = 3,
}

public sealed record EffectivePlan(PlanCode Code, PlanLimits Limits, EffectivePlanSource Source);

/// <summary>
/// Tenantning HOZIRGI limitlari. Qoidalar tartibi:
/// 1) tenant holati (Suspended va h.k.) chaqiruvchida tekshiriladi;
/// 2) aktiv, muddati o'tmagan obuna — o'sha tarif;
/// 3) aks holda Free qatori — rad etish emas, pasaytirish.
///
/// Muddat har chaqiruvda "dangasa" hisoblanadi: fon vazifasi kerak emas va
/// muddat tugashi edge'ga tarif o'zgarishi bilan bir xil yo'l orqali yetadi.
/// </summary>
public sealed class EffectivePlanResolver(IAccessDbContext db, TimeProvider timeProvider)
{
    public async Task<EffectivePlan> ResolveAsync(int tenantId, CancellationToken cancellationToken = default)
    {
        // AsNoTracking: kontekst oldin shu qatorlarni kuzatgan bo'lsa ham
        // bazadagi joriy qiymat o'qiladi (katalog tahriri darhol ko'rinadi).
        var subscription = await db.Subscriptions
            .AsNoTracking()
            .Include(s => s.Plan)
            .SingleOrDefaultAsync(s => s.TenantId == tenantId, cancellationToken);

        if (subscription is null)
        {
            return await FreeAsync(EffectivePlanSource.NoSubscription, cancellationToken);
        }

        if (subscription.Status == SubscriptionStatus.Canceled)
        {
            return await FreeAsync(EffectivePlanSource.Canceled, cancellationToken);
        }

        var now = timeProvider.GetUtcNow();
        if (subscription.PeriodEnd is { } end && end <= now)
        {
            return await FreeAsync(EffectivePlanSource.Expired, cancellationToken);
        }

        return new EffectivePlan(
            subscription.Plan.Code,
            subscription.Plan.ToLimits(),
            EffectivePlanSource.Subscription);
    }

    private async Task<EffectivePlan> FreeAsync(EffectivePlanSource source, CancellationToken cancellationToken)
    {
        var free = await db.Plans.AsNoTracking().GetFreeAsync(cancellationToken);
        return new EffectivePlan(free.Code, free.ToLimits(), source);
    }
}
