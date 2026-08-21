using AccessServer.Domain.Enums;

namespace AccessServer.Domain.Entities;

public sealed class User : Entity
{
    public int TenantId { get; set; }

    // Navigatsiya xossalari `required` emas: ularni EF to'ldiradi, kod esa
    // entity yaratishda majburan bog'lashga majbur bo'lmasligi kerak.
    public Tenant Tenant { get; set; } = null!;

    public required string FullName { get; set; }

    public required string Email { get; set; }

    /// <summary>
    /// Faqat hash. Ochiq parol hech qachon saqlanmaydi (DEV_SPEC §6.5 A-S1).
    /// Foydalanuvchi faqat OAuth orqali kirsa null bo'ladi.
    /// </summary>
    public string? PasswordHash { get; set; }

    // OAuth provayderining `sub` qiymati — access token emas.
    // Access token saqlash foydalanuvchi nomidan API chaqirmasak keraksiz
    // va ortiqcha xavf (DEV_SPEC §6.1 A-5).
    public string? GithubId { get; set; }

    public string? GoogleId { get; set; }

    public DateTimeOffset? EmailVerifiedAt { get; set; }

    public UserStatus Status { get; set; } = UserStatus.Active;

    /// <summary>Marketing xabarlariga obuna.</summary>
    public bool Subscribe { get; set; }

    public ICollection<UserVerificationToken> VerificationTokens { get; set; } = [];

    public bool IsEmailVerified => EmailVerifiedAt is not null;
}
