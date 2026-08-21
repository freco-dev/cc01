using System.ComponentModel.DataAnnotations;

namespace AccessServer.Infrastructure.Auth;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    /// <summary>
    /// Imzolash kaliti. Kamida 32 bayt (256 bit) — HS256 uchun minimum.
    /// Konfiguratsiyadan emas, sir menejeridan/env'dan kelishi kerak.
    /// </summary>
    [Required(AllowEmptyStrings = false)]
    [MinLength(32, ErrorMessage = "Jwt:SigningKey kamida 32 belgi bo'lishi kerak.")]
    public string SigningKey { get; set; } = string.Empty;

    [Required(AllowEmptyStrings = false)]
    public string Issuer { get; set; } = "cc01-access";

    [Required(AllowEmptyStrings = false)]
    public string Audience { get; set; } = "cc01-dashboard";

    [Range(1, 24 * 60)]
    public int LifetimeMinutes { get; set; } = 60;
}
