using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace AccessServer.Application.Usage;

/// <summary>Proto'dagi UsageWindow — o'zgartirilmagan, hali tekshirilmagan qiymatlar.</summary>
/// <param name="TenantSlug">Tenant slug'i (proto'da <c>tenant_id</c>), masalan "t_9f3a".</param>
/// <param name="WindowStart">Unix sekund.</param>
/// <param name="WindowEnd">Unix sekund.</param>
public sealed record UsageWindowInput(
    string TenantSlug,
    string TunnelId,
    long WindowStart,
    long WindowEnd,
    ulong BytesIn,
    ulong BytesOut,
    uint Connections,
    uint Rejected);

/// <param name="ReportedBy">Edge'ning mTLS CN'i yoki "plaintext".</param>
public sealed record RecordUsageCommand(IReadOnlyList<UsageWindowInput> Windows, string ReportedBy);

/// <param name="Received">Hisobotdagi oynalar soni = qayta ishlangani (edge'ga "accepted").</param>
/// <param name="Inserted">Yangi qo'shilgan.</param>
/// <param name="Duplicate">Allaqachon bor edi (edge qayta yuborgan) — tashlab yuborildi.</param>
/// <param name="Dropped">Noto'g'ri yoki tenant noma'lum — tashlab yuborildi.</param>
public sealed record RecordUsageOutcome(int Received, int Inserted, int Duplicate, int Dropped);

/// <summary>Oyna nima uchun tashlandi (log uchun).</summary>
public enum UsageDropReason
{
    TenantUnknown,
    TunnelIdInvalid,
    WindowInverted,
    WindowTooLong,
    WindowTooOld,
    WindowInFuture,
}

/// <summary>
/// Edge'ning usage hisobotini saqlaydi (proto: ReportUsage).
///
/// Har bir oyna MUSTAQIL tekshiriladi: noto'g'risi yoki tenanti noma'lumi
/// Warning bilan tashlanadi, qolganlari saqlanadi. Butun hisobot hech qachon
/// shu sabab rad etilmaydi — aks holda edge uni cheksiz qayta yuborardi.
///
/// Idempotent: (tunnel_id, window_start) bo'yicha takror jimgina tashlanadi
/// (birinchi yozuv yutadi). Shuning uchun natijadagi <c>Received</c> —
/// qo'shilgan + takror + tashlangan — edge navbatidan o'chirishi mumkin
/// bo'lgan son. Baza xatosi istisno sifatida chiqadi: edge hisobotni
/// saqlab qoladi va keyin qayta yuboradi.
/// </summary>
public sealed class RecordUsageHandler(
    IUsageStore store,
    TimeProvider timeProvider,
    ILogger<RecordUsageHandler> logger)
{
    /// <summary>Edge ≤500 yuboradi; zaxira bilan.</summary>
    public const int MaxBatchSize = 1000;

    public static readonly TimeSpan MaxWindowDuration = TimeSpan.FromHours(1);

    /// <summary>Edge ancha vaqt AP'ga yeta olmagan bo'lsa ham — bundan eskisi tashlanadi.</summary>
    public static readonly TimeSpan MaxWindowAge = TimeSpan.FromDays(7);

    /// <summary>Edge va AP soatlari orasidagi ruxsat etilgan farq.</summary>
    public static readonly TimeSpan MaxClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>tenants.slug ustuni uzunligi.</summary>
    private const int MaxTenantSlugLength = 32;

    public async Task<Result<RecordUsageOutcome>> HandleAsync(
        RecordUsageCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (command.Windows.Count > MaxBatchSize)
        {
            return UsageErrors.BatchTooLarge;
        }

        var received = command.Windows.Count;
        if (received == 0)
        {
            return new RecordUsageOutcome(0, 0, 0, 0);
        }

        var reportedBy = NormalizeReporter(command.ReportedBy);
        var now = timeProvider.GetUtcNow();
        var nowUnix = now.ToUnixTimeSeconds();
        var minStart = nowUnix - (long)MaxWindowAge.TotalSeconds;
        var maxEnd = nowUnix + (long)MaxClockSkew.TotalSeconds;

        var drafts = new List<UsageRecordDraft>(received);
        var dropped = new Dictionary<UsageDropReason, int>();

        foreach (var window in command.Windows)
        {
            var reason = Validate(window, minStart, maxEnd);
            if (reason is { } r)
            {
                dropped[r] = dropped.GetValueOrDefault(r) + 1;
                continue;
            }

            drafts.Add(new UsageRecordDraft(
                window.TenantSlug,
                window.TunnelId,
                DateTimeOffset.FromUnixTimeSeconds(window.WindowStart),
                DateTimeOffset.FromUnixTimeSeconds(window.WindowEnd),
                ClampToLong(window.BytesIn),
                ClampToLong(window.BytesOut),
                ClampToInt(window.Connections),
                ClampToInt(window.Rejected)));
        }

        var inserted = 0;
        var duplicate = 0;

        if (drafts.Count > 0)
        {
            var outcome = await store.InsertAsync(drafts, reportedBy, now, cancellationToken);

            var unknownTenant = drafts.Count - outcome.KnownTenant;
            if (unknownTenant > 0)
            {
                dropped[UsageDropReason.TenantUnknown] =
                    dropped.GetValueOrDefault(UsageDropReason.TenantUnknown) + unknownTenant;
            }

            inserted = outcome.Inserted;
            duplicate = outcome.KnownTenant - outcome.Inserted;
        }

        var droppedTotal = dropped.Values.Sum();
        if (droppedTotal > 0)
        {
            // Faqat sonlar va sabablar: tenant slug'i, tunnel_id va boshqa
            // klient qiymatlari log'ga yozilmaydi (A-S9, log in'yeksiyasi).
            logger.LogWarning(
                "Usage: {Dropped} oyna tashlandi ({Reasons}), edge={ReportedBy}",
                droppedTotal,
                FormatReasons(dropped),
                reportedBy);
        }

        logger.LogInformation(
            "Usage hisoboti: {Received} oyna — {Inserted} yangi, {Duplicate} takror, {Dropped} tashlandi (edge={ReportedBy})",
            received,
            inserted,
            duplicate,
            droppedTotal,
            reportedBy);

        return new RecordUsageOutcome(received, inserted, duplicate, droppedTotal);
    }

    /// <summary>
    /// Tekshiruvlar tartibi muhim: vaqt chegaralari ayirishdan OLDIN — shunda
    /// <c>end − start</c> long'da to'lib ketmaydi.
    /// </summary>
    private static UsageDropReason? Validate(UsageWindowInput window, long minStart, long maxEnd)
    {
        // Slug formati noto'g'ri bo'lsa baza so'ralmaydi: Postgres matnda
        // U+0000 ni qabul qilmaydi — bitta shunday oyna butun hisobotni
        // yiqitib, edge'ni cheksiz qayta urinishga majburlardi.
        if (!IsPlainText(window.TenantSlug, MaxTenantSlugLength))
        {
            return UsageDropReason.TenantUnknown;
        }

        if (!IsPlainText(window.TunnelId, UsageRecord.TunnelIdMaxLength))
        {
            return UsageDropReason.TunnelIdInvalid;
        }

        if (window.WindowStart < minStart)
        {
            return UsageDropReason.WindowTooOld;
        }

        if (window.WindowEnd > maxEnd)
        {
            return UsageDropReason.WindowInFuture;
        }

        if (window.WindowEnd <= window.WindowStart)
        {
            return UsageDropReason.WindowInverted;
        }

        if (window.WindowEnd - window.WindowStart > (long)MaxWindowDuration.TotalSeconds)
        {
            return UsageDropReason.WindowTooLong;
        }

        return null;
    }

    private static bool IsPlainText(string? value, int maxLength) =>
        !string.IsNullOrEmpty(value)
        && value.Length <= maxLength
        && !value.Any(char.IsControl);

    private static long ClampToLong(ulong value) => value > long.MaxValue ? long.MaxValue : (long)value;

    private static int ClampToInt(uint value) => value > int.MaxValue ? int.MaxValue : (int)value;

    /// <summary>
    /// reported_by — varchar(64). CN allowlist'dan o'tgan, lekin baribir
    /// cheklanadi: uzun qiymat butun hisobotni baza xatosiga aylantirmasin.
    /// </summary>
    private static string NormalizeReporter(string? reportedBy)
    {
        if (string.IsNullOrEmpty(reportedBy))
        {
            return UsageRecord.PlaintextReporter;
        }

        var cleaned = new string(reportedBy.Select(c => char.IsControl(c) ? '?' : c).ToArray());
        return cleaned.Length <= UsageRecord.ReportedByMaxLength
            ? cleaned
            : cleaned[..UsageRecord.ReportedByMaxLength];
    }

    private static string FormatReasons(Dictionary<UsageDropReason, int> dropped) =>
        string.Join(", ", dropped
            .OrderBy(pair => pair.Key)
            .Select(pair => $"{pair.Key}={pair.Value}"));
}
