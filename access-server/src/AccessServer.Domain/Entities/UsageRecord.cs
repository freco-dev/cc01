namespace AccessServer.Domain.Entities;

/// <summary>
/// Edge yuborgan bitta usage oynasi (proto/cc01/v1/access.proto, UsageWindow):
/// bitta tunnelning [WindowStart, WindowEnd) oralig'idagi trafigi.
///
/// Edge har bir ochiq tunnel uchun har intervalda oyna yuboradi — trafik
/// bo'lmasa ham. Shuning uchun oynalar uzunligining yig'indisi haqiqiy
/// tunnel-soatni beradi.
///
/// Qator faqat qo'shiladi, hech qachon yangilanmaydi: (TunnelId, WindowStart)
/// unique — edge qayta yuborgan oyna jimgina tashlanadi (birinchi yozuv
/// yutadi). Qo'shish xom SQL bilan (qarang Infrastructure UsageStore).
/// </summary>
public sealed class UsageRecord : Entity
{
    public const int TunnelIdMaxLength = 128;

    public const int ReportedByMaxLength = 64;

    /// <summary>Ichki listener mTLS'siz (loopback h2c) bo'lganda <see cref="ReportedBy"/>.</summary>
    public const string PlaintextReporter = "plaintext";

    public int TenantId { get; set; }

    public Tenant Tenant { get; set; } = null!;

    /// <summary>Edge bergan tunnel identifikatori (shaffof satr).</summary>
    public required string TunnelId { get; set; }

    public DateTimeOffset WindowStart { get; set; }

    public DateTimeOffset WindowEnd { get; set; }

    /// <summary>uint64 dan; long.MaxValue dan kattasi long.MaxValue ga qisiladi.</summary>
    public long BytesIn { get; set; }

    public long BytesOut { get; set; }

    public int Connections { get; set; }

    public int Rejected { get; set; }

    /// <summary>
    /// Hisobotni yuborgan edge: mTLS klient sertifikatining Subject CN'i,
    /// mTLS bo'lmasa <see cref="PlaintextReporter"/>.
    /// </summary>
    public required string ReportedBy { get; set; }
}
