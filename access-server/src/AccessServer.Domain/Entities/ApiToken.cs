namespace AccessServer.Domain.Entities;

/// <summary>
/// CLI va CI uchun API tokeni. Token va subdomain ataylab ajratilgan: token
/// bekor qilinadi va aylantiriladi, subdomain esa tenantda qoladi.
/// </summary>
public sealed class ApiToken : Entity
{
    public int TenantId { get; set; }

    public Tenant Tenant { get; set; } = null!;

    /// <summary>Tokenni yaratgan foydalanuvchi — audit uchun.</summary>
    public int CreatedByUserId { get; set; }

    public User CreatedByUser { get; set; } = null!;

    /// <summary>
    /// Tokenning ochiq qismi, masalan "cc01_live_a1b2c3d4". Qidiruv shu bo'yicha
    /// ketadi — sirni bazadan qidirib bo'lmaydi. Log'ga faqat shu yoziladi.
    /// </summary>
    public required string Prefix { get; set; }

    /// <summary>SHA-256(to'liq token). Solishtirish doimiy vaqtda bajariladi.</summary>
    public required byte[] TokenHash { get; set; }

    /// <summary>Foydalanuvchi bergan nom: "laptop", "ci-runner".</summary>
    public required string Name { get; set; }

    public DateTimeOffset? LastUsedAt { get; set; }

    /// <summary>
    /// Absolyut muddat. Nisbiy TimeSpan emas — aks holda "qachondan boshlab"
    /// degan savol javobsiz qoladi va renew mantiqi noaniq bo'ladi.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public bool IsUsableAt(DateTimeOffset now) =>
        RevokedAt is null && (ExpiresAt is null || ExpiresAt > now);
}
