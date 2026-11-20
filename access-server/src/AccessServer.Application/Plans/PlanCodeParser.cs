using AccessServer.Domain.Enums;

namespace AccessServer.Application.Plans;

/// <summary>
/// Tarif kodining tashqi (wire) ko'rinishi: "free", "pro", "enterprise".
///
/// ⚠️ <c>Enum.TryParse</c> ATAYLAB ishlatilmaydi: u "1" ni Pro, "Pro,Free" ni
/// bayroqlar birikmasi, " pro" ni esa bo'shliqni kesib qabul qiladi. Tarif —
/// pul bilan bog'liq imtiyoz, shuning uchun faqat aniq ro'yxat.
/// </summary>
public static class PlanCodeParser
{
    public static bool TryParse(string? raw, out PlanCode code)
    {
        switch (raw)
        {
            case "free":
                code = PlanCode.Free;
                return true;

            case "pro":
                code = PlanCode.Pro;
                return true;

            case "enterprise":
                code = PlanCode.Enterprise;
                return true;

            default:
                code = default;
                return false;
        }
    }

    public static string ToWire(PlanCode code) => code switch
    {
        PlanCode.Free => "free",
        PlanCode.Pro => "pro",
        PlanCode.Enterprise => "enterprise",
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, "Noma'lum tarif kodi."),
    };
}
