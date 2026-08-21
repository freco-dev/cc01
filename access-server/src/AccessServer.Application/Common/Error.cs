namespace AccessServer.Application.Common;

/// <summary>
/// Kutilgan muvaffaqiyatsizlik. Istisno EMAS: "email band" — bu dasturning
/// normal ishlash yo'li, istisno esa kutilmagan holat uchun.
/// `Code` mashina uchun (API javobida), `Message` odam uchun.
/// </summary>
public sealed record Error(string Code, string Message)
{
    public static Error Conflict(string code, string message) => new(code, message);

    public static Error Validation(string code, string message) => new(code, message);

    public static Error NotFound(string code, string message) => new(code, message);

    public static Error Unauthorized(string code, string message) => new(code, message);
}
