using AccessServer.Application.Common;

namespace AccessServer.Application.Auth;

public static class AuthErrors
{
    public static readonly Error EmailInvalid =
        Error.Validation("EMAIL_INVALID", "Email manzili noto'g'ri.");

    public static readonly Error EmailTaken =
        Error.Conflict("EMAIL_TAKEN", "Bu email allaqachon ro'yxatdan o'tgan.");

    public static readonly Error PasswordTooShort =
        Error.Validation("PASSWORD_TOO_SHORT",
            $"Parol kamida {RegisterUserHandler.MinPasswordLength} belgidan iborat bo'lishi kerak.");

    public static readonly Error FullNameRequired =
        Error.Validation("FULL_NAME_REQUIRED", "Ism kiritilishi shart.");

    // Login xatosi ataylab umumiy: "email topilmadi" va "parol noto'g'ri"
    // ni ajratish hisob mavjudligini oshkor qiladi (user enumeration).
    public static readonly Error InvalidCredentials =
        Error.Unauthorized("INVALID_CREDENTIALS", "Email yoki parol noto'g'ri.");

    public static readonly Error AccountSuspended =
        Error.Unauthorized("ACCOUNT_SUSPENDED", "Hisob to'xtatilgan.");

    public static readonly Error VerificationTokenInvalid =
        Error.NotFound("VERIFICATION_TOKEN_INVALID",
            "Tasdiqlash havolasi yaroqsiz yoki muddati o'tgan.");
}
