using AccessServer.Application.Common;
using AccessServer.Application.Validation;

namespace AccessServer.Application.Subdomains;

public static class SubdomainErrors
{
    public static readonly Error Taken =
        Error.Conflict("SUBDOMAIN_TAKEN", "Bu subdomain allaqachon band.");

    public static readonly Error NotFound =
        Error.NotFound("SUBDOMAIN_NOT_FOUND", "Subdomain topilmadi.");

    public static readonly Error QuotaExceeded =
        Error.Conflict("SUBDOMAIN_QUOTA_EXCEEDED",
            "Tarif bo'yicha subdomainlar soni limitiga yetdingiz.");

    public static Error ForValidation(SubdomainValidation validation) => validation switch
    {
        SubdomainValidation.Empty =>
            Error.Validation("SUBDOMAIN_EMPTY", "Subdomain kiritilishi shart."),

        SubdomainValidation.BadLength =>
            Error.Validation("SUBDOMAIN_BAD_LENGTH",
                $"Uzunlik {SubdomainRules.MinLength}–{SubdomainRules.MaxLength} belgi bo'lishi kerak."),

        SubdomainValidation.BadFormat =>
            Error.Validation("SUBDOMAIN_BAD_FORMAT",
                "Faqat kichik harf, raqam va defis; defis bilan boshlanmaydi/tugamaydi "
                + "va ketma-ket ikkita defis bo'lmaydi."),

        SubdomainValidation.Reserved =>
            Error.Validation("SUBDOMAIN_RESERVED", "Bu nom platforma tomonidan band qilingan."),

        _ => Error.Validation("SUBDOMAIN_INVALID", "Subdomain yaroqsiz."),
    };
}
