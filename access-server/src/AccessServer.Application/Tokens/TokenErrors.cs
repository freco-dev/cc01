using AccessServer.Application.Common;

namespace AccessServer.Application.Tokens;

public static class TokenErrors
{
    public static readonly Error NameRequired =
        Error.Validation("TOKEN_NAME_REQUIRED", "Token uchun nom kiritilishi shart.");

    public static readonly Error NotFound =
        Error.NotFound("TOKEN_NOT_FOUND", "Token topilmadi.");

    public static readonly Error EmailNotVerified =
        Error.Validation("EMAIL_NOT_VERIFIED",
            "Token yaratishdan oldin email tasdiqlanishi kerak.");
}
