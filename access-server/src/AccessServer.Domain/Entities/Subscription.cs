using AccessServer.Domain.Enums;

namespace AccessServer.Domain.Entities;

/// <summary>
/// Tenantning joriy tarifi. Har bir tenantda aniq BITTA qator: tarif
/// o'zgarganda qator joyida yangilanadi, tarix esa audit_events'da qoladi.
/// Shunda "eski qatorni yopish, yangisini qo'shish" tartibi va unga
/// bog'liq poygalar umuman paydo bo'lmaydi.
/// </summary>
public sealed class Subscription : Entity
{
    public int TenantId { get; set; }

    public Tenant Tenant { get; set; } = null!;

    public int PlanId { get; set; }

    public Plan Plan { get; set; } = null!;

    public SubscriptionStatus Status { get; set; } = SubscriptionStatus.Active;

    public DateTimeOffset PeriodStart { get; set; }

    /// <summary>
    /// null = muddatsiz. Muddat o'tgach tenant Free limitlariga tushadi —
    /// buni fon vazifasi emas, har bir avtorizatsiya o'zi hisoblaydi.
    /// </summary>
    public DateTimeOffset? PeriodEnd { get; set; }

    /// <summary>Postgres `xmin` — optimistik parallellik tokeni.</summary>
    public uint Version { get; set; }
}
