using System.Data.Common;
using System.Text.Json;
using System.Text.RegularExpressions;
using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Domain.Entities;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AccessServer.Application.Plans;

/// <param name="Plan">Wire ko'rinishi: "free", "pro", "enterprise".</param>
/// <param name="PeriodEnd">null = muddatsiz.</param>
/// <param name="Actor">Operator nomi (masalan "aziz"), auditga yoziladi.</param>
public sealed record ChangePlanCommand(
    string TenantSlug,
    string Plan,
    DateTimeOffset? PeriodEnd,
    string Actor,
    string? Reason,
    string? Ip);

/// <param name="Changed">false — so'ralgan holat allaqachon amalda edi (yozuv ham, audit ham yo'q).</param>
public sealed record SubscriptionView(
    string Tenant,
    PlanCode Plan,
    SubscriptionStatus Status,
    DateTimeOffset PeriodStart,
    DateTimeOffset? PeriodEnd,
    bool Changed);

/// <summary>
/// Tenant tarifini o'zgartiradi (hozircha faqat operator, ichki listener
/// orqali; Faza 3 billing ham shu handler'ni chaqiradi).
///
/// Obuna qatori JOYIDA yangilanadi va audit yozuvi bilan birga BITTA
/// SaveChanges'da saqlanadi — "tarif o'zgardi, audit yozilmadi" holati
/// bo'lmaydi. Parallel o'zgarishni xmin (yoki birinchi qatorni bir vaqtda
/// qo'shishda unique indeks) ushlaydi → SUBSCRIPTION_CONFLICT.
///
/// Edge yangi limitlarni keyingi lease yangilanishida oladi (≤33 s).
/// </summary>
public sealed partial class ChangePlanHandler(
    IAccessDbContext db,
    TimeProvider timeProvider,
    ILogger<ChangePlanHandler> logger)
{
    public const string AuditAction = "plan.changed";

    private const string ActorPrefix = "operator:";

    /// <summary>audit_events.actor 64 belgi; "operator:" prefiksi ham shunga kiradi.</summary>
    public const int MaxActorLength = 64 - 9;

    public const int MaxReasonLength = 200;

    /// <summary>
    /// <c>\z</c>, <c>$</c> emas: .NET'da <c>$</c> oxiridagi <c>\n</c> dan oldin
    /// ham mos keladi — "aziz\n" o'tib, audit va logga yangi qator tushardi.
    /// </summary>
    [GeneratedRegex(@"\A[A-Za-z0-9._-]+\z", RegexOptions.CultureInvariant)]
    private static partial Regex ActorPattern { get; }

    public async Task<Result<SubscriptionView>> HandleAsync(
        ChangePlanCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (!PlanCodeParser.TryParse(command.Plan, out var code))
        {
            return PlanErrors.PlanUnknown;
        }

        if (string.IsNullOrEmpty(command.Actor)
            || command.Actor.Length > MaxActorLength
            || !ActorPattern.IsMatch(command.Actor))
        {
            return PlanErrors.ActorInvalid;
        }

        if (command.Reason is { } reason
            && (reason.Length > MaxReasonLength || !IsPlainText(reason)))
        {
            return PlanErrors.ReasonInvalid;
        }

        var now = timeProvider.GetUtcNow();
        var periodEnd = NormalizePeriodEnd(command.PeriodEnd);
        if (periodEnd <= now)
        {
            return PlanErrors.PeriodInvalid;
        }

        var tenant = await db.Tenants
            .Include(t => t.Subscription)
            .ThenInclude(s => s!.Plan)
            .SingleOrDefaultAsync(t => t.Slug == command.TenantSlug, cancellationToken);

        // Suspended tenantga ruxsat: to'xtatish va tarif — mustaqil o'qlar.
        if (tenant is null || tenant.Status == TenantStatus.Deleted)
        {
            return PlanErrors.TenantNotFound;
        }

        // Katalogda bo'lishi shart (HasData). Yo'q bo'lsa — konfiguratsiya
        // xatosi, kutilgan muvaffaqiyatsizlik emas.
        var plan = await db.Plans.SingleOrDefaultAsync(p => p.Code == code, cancellationToken)
            ?? throw new InvalidOperationException(
                $"plans jadvalida {code} yo'q — migratsiya qo'llanmagan");

        var subscription = tenant.Subscription;

        if (subscription is not null
            && subscription.Status == SubscriptionStatus.Active
            && subscription.PlanId == plan.Id
            && subscription.PeriodEnd == periodEnd)
        {
            return ToView(tenant.Slug, plan.Code, subscription, changed: false);
        }

        var from = subscription is null ? null : PlanCodeParser.ToWire(subscription.Plan.Code);

        if (subscription is null)
        {
            subscription = new Subscription { TenantId = tenant.Id };
            db.Subscriptions.Add(subscription);
        }

        subscription.Plan = plan;
        subscription.PlanId = plan.Id;
        subscription.Status = SubscriptionStatus.Active;
        subscription.PeriodStart = now;
        subscription.PeriodEnd = periodEnd;

        // Shaxsiy ma'lumot (email, ism) YOZILMAYDI — faqat tarif va sabab.
        db.AuditEvents.Add(new AuditEvent
        {
            TenantId = tenant.Id,
            Actor = ActorPrefix + command.Actor,
            Action = AuditAction,
            Target = "tenant:" + tenant.Slug,
            Ip = command.Ip,
            Metadata = JsonSerializer.Serialize(
                new AuditMetadata(
                    from, PlanCodeParser.ToWire(plan.Code), periodEnd, command.Reason),
                JsonSerializerOptions.Web),
        });

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (IsConcurrentChange(ex))
        {
            // Faqat haqiqiy poyga: xmin o'zgargan yoki birinchi qatorni boshqa
            // so'rov qo'shib ulgurgan. Boshqa xatolar (ma'lumot xatosi, baza
            // uzilishi) 409 "qayta urinib ko'ring" bo'lib ko'rinmasligi kerak —
            // qayta urinish ularni tuzatmaydi, shuning uchun ular yuqoriga
            // ko'tariladi (500).
            return PlanErrors.Conflict;
        }

        logger.LogInformation(
            "Tarif o'zgardi: {Slug} {From}->{To} actor={Actor}",
            tenant.Slug, from ?? "-", PlanCodeParser.ToWire(plan.Code), command.Actor);

        return ToView(tenant.Slug, plan.Code, subscription, changed: true);
    }

    /// <summary>Postgres unique_violation.</summary>
    private const string UniqueViolation = "23505";

    private static bool IsConcurrentChange(DbUpdateException ex) =>
        ex is DbUpdateConcurrencyException
        || ex.InnerException is DbException { SqlState: UniqueViolation };

    /// <summary>
    /// Boshqaruv belgilari (U+0000 ham) va juftsiz surrogatlar yo'q. U+0000
    /// ni jsonb umuman qabul qilmaydi (22P05), qolganlari audit va logni
    /// buzadi. Tekshiruv saqlashdan OLDIN — aks holda xato 400 emas, baza
    /// xatosi bo'lib chiqardi.
    /// </summary>
    private static bool IsPlainText(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];

            if (char.IsControl(c) || char.IsLowSurrogate(c))
            {
                return false;
            }

            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1]))
                {
                    return false;
                }

                i++;
            }
        }

        return true;
    }

    private static SubscriptionView ToView(
        string slug, PlanCode code, Subscription subscription, bool changed) =>
        new(slug, code, subscription.Status, subscription.PeriodStart, subscription.PeriodEnd, changed);

    /// <summary>
    /// Postgres timestamptz mikrosekund aniqligida saqlaydi. Kesilmasa ayni
    /// bir so'rovni takrorlash "o'zgardi" deb qayta yozilardi (no-op buziladi).
    /// </summary>
    private static DateTimeOffset? NormalizePeriodEnd(DateTimeOffset? value) =>
        value is { } v
            ? new DateTimeOffset(v.UtcTicks - (v.UtcTicks % 10), TimeSpan.Zero)
            : null;

    private sealed record AuditMetadata(string? From, string To, DateTimeOffset? PeriodEnd, string? Reason);
}
