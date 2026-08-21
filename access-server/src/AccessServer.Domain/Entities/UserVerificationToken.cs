using AccessServer.Domain.Enums;

namespace AccessServer.Domain.Entities;

/// <summary>
/// Bir martalik tasdiqlash tokeni (email tasdiqlash, parol tiklash).
/// `Purpose` bilan bitta jadval ikkala stsenariyni qoplaydi — parol tiklash
/// uchun deyarli bir xil ikkinchi jadval yaratishning hojati yo'q.
/// </summary>
public sealed class UserVerificationToken : Entity
{
    public int UserId { get; set; }

    public User User { get; set; } = null!;

    public VerificationPurpose Purpose { get; set; }

    /// <summary>
    /// SHA-256(token). Xom token faqat foydalanuvchiga yuborilgan xatda
    /// bo'ladi — bazadan uni tiklab bo'lmaydi.
    /// </summary>
    public required byte[] TokenHash { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>Ishlatilgan vaqt. Bir marta ishlatilgach qayta ishlamaydi.</summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    public bool IsUsableAt(DateTimeOffset now) => ConsumedAt is null && ExpiresAt > now;
}
