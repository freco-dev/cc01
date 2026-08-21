using AccessServer.Application.Common;

namespace AccessServer.Application.Auth;

public static class OAuthErrors
{
    public static readonly Error ProviderUnknown =
        Error.NotFound("OAUTH_PROVIDER_UNKNOWN", "Bunday provayder qo'llab-quvvatlanmaydi.");

    public static readonly Error ProviderNotConfigured =
        Error.Validation("OAUTH_PROVIDER_NOT_CONFIGURED",
            "Bu provayder serverda sozlanmagan (client id/secret yo'q).");

    public static readonly Error SubjectMissing =
        Error.Validation("OAUTH_SUBJECT_MISSING",
            "Provayder foydalanuvchi identifikatorini qaytarmadi.");

    public static readonly Error EmailMissing =
        Error.Validation("OAUTH_EMAIL_MISSING",
            "Provayderdan email olinmadi. Profilingizda email ochiq ekanini tekshiring.");

    /// <summary>
    /// Tasdiqlanmagan email bilan mavjud hisobga bog'lanish — hisobni
    /// egallab olishning klassik yo'li: tajovuzkor begona emailni o'z
    /// provayder hisobiga yozib, o'sha email egasining hisobiga kiradi.
    /// </summary>
    public static readonly Error EmailUnverified =
        Error.Validation("OAUTH_EMAIL_UNVERIFIED",
            "Provayder emailni tasdiqlangan deb belgilamagan. "
            + "Avval provayderda emailni tasdiqlang.");

    public static readonly Error NotAuthenticated =
        Error.Unauthorized("OAUTH_NOT_AUTHENTICATED",
            "Provayder sessiyasi topilmadi yoki muddati o'tgan. Qaytadan urinib ko'ring.");
}
