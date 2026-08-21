using System.Text.RegularExpressions;

namespace AccessServer.Application.Validation;

/// <summary>
/// Subdomain qoidalari. Yagona manba: proto/cc01/v1/tunnel.proto,
/// TunnelRequested.subdomain (DEV_SPEC §6.6).
///
/// ⚠️ Bu qoidalar Go tomonda core-server/utils.go da ham amalga oshirilgan.
/// Ikkalasi bir xil natija berishi SHART — aks holda foydalanuvchi dashboard'da
/// band qilgan nom edge'da rad etiladi. test/contract ikkalasini solishtiradi.
/// Shu faylni o'zgartirsangiz, Go tomonini ham o'zgartiring.
/// </summary>
public static partial class SubdomainRules
{
    public const int MinLength = 3;
    public const int MaxLength = 38;

    /// <summary>
    /// Platforma o'zi ishlatadigan nomlar. Foydalanuvchiga berilmaydi.
    /// </summary>
    public static readonly IReadOnlySet<string> DenyList = new HashSet<string>(StringComparer.Ordinal)
    {
        "www", "api", "admin", "cp", "edge", "relay", "stun", "mail",
        "ns1", "ns2", "static", "cdn", "status", "docs", "app",
        "dashboard", "internal",
    };

    [GeneratedRegex(@"^[a-z0-9](?:[a-z0-9]|-[a-z0-9])*$", RegexOptions.CultureInvariant)]
    private static partial Regex FormatPattern { get; }

    public static SubdomainValidation Validate(string? candidate)
    {
        if (string.IsNullOrEmpty(candidate))
        {
            return SubdomainValidation.Empty;
        }

        // Uzunlik alohida tekshiriladi: regexdagi guruh o'zgaruvchan kenglikda,
        // shuning uchun u yolg'iz o'zi yuqori chegarani ushlab tura olmaydi.
        if (candidate.Length < MinLength || candidate.Length > MaxLength)
        {
            return SubdomainValidation.BadLength;
        }

        if (!FormatPattern.IsMatch(candidate))
        {
            return SubdomainValidation.BadFormat;
        }

        return DenyList.Contains(candidate)
            ? SubdomainValidation.Reserved
            : SubdomainValidation.Ok;
    }

    public static bool IsValid(string? candidate) => Validate(candidate) == SubdomainValidation.Ok;
}

public enum SubdomainValidation
{
    Ok = 0,
    Empty = 1,
    BadLength = 2,
    BadFormat = 3,
    Reserved = 4,
}
