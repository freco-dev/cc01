using AccessServer.Application.Common;

namespace AccessServer.Application.Plans;

public static class PlanErrors
{
    public static readonly Error TenantNotFound =
        Error.NotFound("TENANT_NOT_FOUND", "Tenant topilmadi.");

    public static readonly Error PlanUnknown =
        Error.Validation("PLAN_UNKNOWN",
            "Noma'lum tarif. Ruxsat etilgan qiymatlar: free, pro, enterprise.");

    public static readonly Error PeriodInvalid =
        Error.Validation("PLAN_PERIOD_INVALID", "Muddat tugashi kelajakda bo'lishi kerak.");

    public static readonly Error ActorInvalid =
        Error.Validation("PLAN_ACTOR_INVALID",
            $"Operator nomi 1–{ChangePlanHandler.MaxActorLength} belgi bo'lishi kerak: "
            + "lotin harfi, raqam, '.', '_' yoki '-' (email emas).");

    public static readonly Error ReasonInvalid =
        Error.Validation("PLAN_REASON_INVALID",
            $"Sabab {ChangePlanHandler.MaxReasonLength} belgidan oshmasligi va boshqaruv "
            + "belgilarisiz (yangi qator, tab, U+0000) bo'lishi kerak.");

    public static readonly Error Conflict =
        Error.Conflict("SUBSCRIPTION_CONFLICT",
            "Obuna bir vaqtda boshqa so'rov bilan o'zgartirildi. Qayta urinib ko'ring.");
}
