using System.Globalization;
using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;

namespace AccessServer.Application.Usage;

/// <param name="TenantId">FAQAT chaqiruvchining JWT'sidagi tenant (A-S15) — so'rovdan olinmaydi.</param>
/// <param name="From">ISO-8601 vaqt; null — <c>to − 30 kun</c>.</param>
/// <param name="To">ISO-8601 vaqt; null — hozir.</param>
public sealed record GetUsageQuery(int TenantId, string? From, string? To);

/// <param name="TunnelHours">Σ(window_end − window_start) / 3600, 2 xonagacha yaxlitlangan.</param>
public sealed record UsageAmountsView(
    long BytesIn,
    long BytesOut,
    long Connections,
    long Rejected,
    decimal TunnelHours);

/// <param name="Date">window_start'ning UTC sanasi.</param>
public sealed record UsageDayView(DateOnly Date, UsageAmountsView Amounts);

/// <param name="From">Amaldagi davr boshi (UTC), shu jumladan.</param>
/// <param name="To">Amaldagi davr oxiri (UTC), shu jumladan EMAS.</param>
public sealed record UsageView(
    DateTimeOffset From,
    DateTimeOffset To,
    UsageAmountsView Totals,
    IReadOnlyList<UsageDayView> Daily);

/// <summary>
/// Dashboard uchun: tenantning [from, to) davridagi bayt, ulanish va
/// tunnel-soat — jami va UTC kunlari bo'yicha. Oyna davrga window_start
/// bo'yicha kiradi. Yig'indi bazada hisoblanadi (IUsageStore).
/// </summary>
public sealed class GetUsageHandler(IUsageStore store, TimeProvider timeProvider)
{
    public const int DefaultRangeDays = 30;

    public const int MaxRangeDays = 400;

    public async Task<Result<UsageView>> HandleAsync(
        GetUsageQuery query,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        if (!TryParseInstant(query.To, out var to) || !TryParseInstant(query.From, out var from))
        {
            return UsageErrors.RangeInvalid;
        }

        var resolvedTo = to ?? timeProvider.GetUtcNow();

        // MinValue atrofida AddDays istisno otadi — bunday davr baribir bo'sh.
        if (from is null && resolvedTo < DateTimeOffset.MinValue.AddDays(DefaultRangeDays))
        {
            return UsageErrors.RangeInvalid;
        }

        var resolvedFrom = from ?? resolvedTo.AddDays(-DefaultRangeDays);

        if (resolvedFrom >= resolvedTo || resolvedTo - resolvedFrom > TimeSpan.FromDays(MaxRangeDays))
        {
            return UsageErrors.RangeInvalid;
        }

        // Npgsql timestamptz'ga faqat UTC (offset 0) yozadi.
        resolvedFrom = resolvedFrom.ToUniversalTime();
        resolvedTo = resolvedTo.ToUniversalTime();

        var aggregate = await store.AggregateAsync(query.TenantId, resolvedFrom, resolvedTo, cancellationToken);

        return new UsageView(
            resolvedFrom,
            resolvedTo,
            ToView(aggregate.Totals),
            aggregate.Daily.Select(day => new UsageDayView(day.Date, ToView(day.Amounts))).ToList());
    }

    /// <summary>null/bo'sh — berilmagan; offset'siz qiymat UTC deb olinadi.</summary>
    private static bool TryParseInstant(string? raw, out DateTimeOffset? value)
    {
        value = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return true;
        }

        if (!DateTimeOffset.TryParse(
                raw,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AllowWhiteSpaces,
                out var parsed))
        {
            return false;
        }

        value = parsed;
        return true;
    }

    private static UsageAmountsView ToView(UsageAmounts amounts) => new(
        amounts.BytesIn,
        amounts.BytesOut,
        amounts.Connections,
        amounts.Rejected,
        Math.Round(amounts.TunnelSeconds / 3600m, 2, MidpointRounding.AwayFromZero));
}
