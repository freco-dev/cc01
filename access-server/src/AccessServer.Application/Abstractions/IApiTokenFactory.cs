namespace AccessServer.Application.Abstractions;

/// <param name="Secret">
/// To'liq token: "cc01_live_&lt;prefiks&gt;_&lt;sir&gt;". Foydalanuvchiga faqat
/// bir marta ko'rsatiladi va hech qayerda saqlanmaydi.
/// </param>
public readonly record struct GeneratedApiToken(string Secret, string Prefix, byte[] Hash);

public interface IApiTokenFactory
{
    GeneratedApiToken Create();

    /// <summary>Kelgan tokendan prefiksni ajratadi (bazadan qidirish uchun).</summary>
    bool TryParsePrefix(string token, out string prefix);

    byte[] ComputeHash(string token);

    /// <summary>Doimiy vaqtda solishtirish — timing attack'ning oldini oladi.</summary>
    bool HashesEqual(byte[] left, byte[] right);
}
