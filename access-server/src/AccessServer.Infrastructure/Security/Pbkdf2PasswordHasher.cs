using System.Security.Cryptography;
using AccessServer.Application.Abstractions;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace AccessServer.Infrastructure.Security;

/// <summary>
/// PBKDF2-SHA256 (DEV_SPEC §6.5 A-S1).
///
/// Saqlash formati o'zini o'zi tavsiflaydi:
///     v1$&lt;iteratsiya&gt;$&lt;salt-base64&gt;$&lt;hash-base64&gt;
/// Shuning uchun iteratsiya sonini oshirganda eski hashlar ishlashda davom
/// etadi va muvaffaqiyatli logindan keyin sekin-asta yangilanadi
/// (`needsRehash`).
/// </summary>
public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    private const string Version = "v1";
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    // OWASP tavsiyasiga yaqin; DEV_SPEC minimumi (100k) dan yuqori.
    private const int CurrentIterations = 210_000;

    public string DummyHash { get; } = BuildDummyHash();

    public string Hash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, CurrentIterations);

        return string.Join('$',
            Version,
            CurrentIterations.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToBase64String(salt),
            Convert.ToBase64String(hash));
    }

    public bool Verify(string password, string hash, out bool needsRehash)
    {
        needsRehash = false;

        if (password is null || !TryParse(hash, out var iterations, out var salt, out var expected))
        {
            return false;
        }

        var actual = Derive(password, salt, iterations);

        // Doimiy vaqtda solishtirish — timing attack'ning oldini oladi.
        if (!CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            return false;
        }

        needsRehash = iterations < CurrentIterations;
        return true;
    }

    private static byte[] Derive(string password, byte[] salt, int iterations) =>
        KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: iterations,
            numBytesRequested: HashBytes);

    private static bool TryParse(
        string? stored,
        out int iterations,
        out byte[] salt,
        out byte[] hash)
    {
        iterations = 0;
        salt = [];
        hash = [];

        if (string.IsNullOrEmpty(stored))
        {
            return false;
        }

        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != Version)
        {
            return false;
        }

        if (!int.TryParse(parts[1], System.Globalization.CultureInfo.InvariantCulture, out iterations)
            || iterations <= 0)
        {
            return false;
        }

        try
        {
            salt = Convert.FromBase64String(parts[2]);
            hash = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        return salt.Length == SaltBytes && hash.Length == HashBytes;
    }

    /// <summary>
    /// Tasodifiy sirdan yasalgan hash: formati to'g'ri, lekin unga mos parol
    /// mavjud emas. Verify uni haqiqiy hash kabi hisoblaydi, demak vaqt sarfi
    /// bir xil bo'ladi.
    /// </summary>
    private static string BuildDummyHash()
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = RandomNumberGenerator.GetBytes(HashBytes);

        return string.Join('$',
            Version,
            CurrentIterations.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToBase64String(salt),
            Convert.ToBase64String(hash));
    }
}
