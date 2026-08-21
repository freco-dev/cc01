using System.Security.Cryptography;
using System.Text;
using AccessServer.Application.Abstractions;

namespace AccessServer.Infrastructure.Security;

/// <summary>
/// Token formati (DEV_SPEC §6.3):
///     cc01_live_&lt;prefiks:8&gt;_&lt;sir:43&gt;
/// Prefiks bazada indekslanadi va log'ga yoziladi; sir hech qayerda
/// saqlanmaydi, faqat SHA-256 hashi.
/// </summary>
public sealed class ApiTokenFactory : IApiTokenFactory
{
    private const string Environment = "live";
    private const int PrefixRandomBytes = 6;   // base64url → 8 belgi
    private const int PrefixCharLength = 8;    // 6 bayt = 48 bit = 8 base64 belgi
    private const int SecretBytes = 32;        // base64url → 43 belgi

    private static readonly string FullPrefix = $"cc01_{Environment}_";

    public GeneratedApiToken Create()
    {
        var prefix = FullPrefix + ToBase64Url(RandomNumberGenerator.GetBytes(PrefixRandomBytes));
        var secretPart = ToBase64Url(RandomNumberGenerator.GetBytes(SecretBytes));

        var full = prefix + "_" + secretPart;

        return new GeneratedApiToken(full, prefix, ComputeHash(full));
    }

    public bool TryParsePrefix(string token, out string prefix)
    {
        prefix = string.Empty;

        if (string.IsNullOrEmpty(token) || !token.StartsWith(FullPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        // ⚠️ Bu yerda `LastIndexOf('_')` ishlatib bo'lMAYDI: sir base64url
        // alifbosida va uning ichida ham '_' uchraydi. Prefiks uzunligi
        // qat'iy ("cc01_live_" + 8 belgi), shuning uchun ajratuvchi aynan
        // shu pozitsiyada bo'lishi shart.
        var separatorIndex = FullPrefix.Length + PrefixCharLength;

        if (token.Length <= separatorIndex || token[separatorIndex] != '_')
        {
            return false;
        }

        prefix = token[..separatorIndex];
        return true;
    }

    public byte[] ComputeHash(string token) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(token));

    public bool HashesEqual(byte[] left, byte[] right) =>
        CryptographicOperations.FixedTimeEquals(left, right);

    private static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
