namespace AccessServer.Application.Abstractions;

/// <summary>Tekshiruvdan o'tgan, saqlashga tayyor usage oynasi (tenant hali slug ko'rinishida).</summary>
public sealed record UsageRecordDraft(
    string TenantSlug,
    string TunnelId,
    DateTimeOffset WindowStart,
    DateTimeOffset WindowEnd,
    long BytesIn,
    long BytesOut,
    int Connections,
    int Rejected);

/// <param name="KnownTenant">Slug'i mavjud tenantga mos kelgan oynalar soni.</param>
/// <param name="Inserted">Shulardan haqiqatda qo'shilgani (qolgani — takror).</param>
public sealed record UsageInsertOutcome(int KnownTenant, int Inserted);

/// <param name="TunnelSeconds">Σ(window_end − window_start), sekund.</param>
public sealed record UsageAmounts(
    long BytesIn,
    long BytesOut,
    long Connections,
    long Rejected,
    long TunnelSeconds)
{
    public static readonly UsageAmounts Zero = new(0, 0, 0, 0, 0);
}

public sealed record UsageDayAmounts(DateOnly Date, UsageAmounts Amounts);

/// <param name="Daily">Faqat ma'lumoti bor UTC kunlar, sana bo'yicha tartiblangan.</param>
public sealed record UsageAggregate(UsageAmounts Totals, IReadOnlyList<UsageDayAmounts> Daily);

/// <summary>
/// usage_records uchun xom SQL. EF LINQ bu yerda yetmaydi: idempotent
/// qo'shish <c>INSERT … ON CONFLICT DO NOTHING</c> talab qiladi, kunlik
/// yig'indi esa UTC sanasi bo'yicha guruhlashni — ikkalasi ham bitta so'rovda.
/// Implementatsiya Infrastructure'da (UsageStore).
/// </summary>
public interface IUsageStore
{
    /// <summary>
    /// Oynalarni bitta so'rovda qo'shadi: slug'i noma'lum tenantning oynasi
    /// o'tkazib yuboriladi, (tunnel_id, window_start) allaqachon bor bo'lsa —
    /// takror, birinchi yozuv qoladi. Baza xatosi — istisno.
    /// </summary>
    Task<UsageInsertOutcome> InsertAsync(
        IReadOnlyList<UsageRecordDraft> drafts,
        string reportedBy,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Tenantning [from, to) dagi oynalari (window_start bo'yicha) — jami va
    /// UTC kunlari bo'yicha, bazada yig'iladi.
    /// </summary>
    Task<UsageAggregate> AggregateAsync(
        int tenantId,
        DateTimeOffset from,
        DateTimeOffset to,
        CancellationToken cancellationToken = default);
}
