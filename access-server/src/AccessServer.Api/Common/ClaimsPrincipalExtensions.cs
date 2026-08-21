using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AccessServer.Infrastructure.Auth;

namespace AccessServer.Api.Common;

public static class ClaimsPrincipalExtensions
{
    public static int GetUserId(this ClaimsPrincipal principal) =>
        ParseRequiredInt(principal, JwtRegisteredClaimNames.Sub);

    public static int GetTenantId(this ClaimsPrincipal principal) =>
        ParseRequiredInt(principal, Cc01Claims.TenantId);

    private static int ParseRequiredInt(ClaimsPrincipal principal, string claimType)
    {
        var raw = principal.FindFirstValue(claimType);

        // Bu yerga faqat autentifikatsiyadan o'tgan so'rov keladi, ya'ni claim
        // bo'lishi shart. Yo'q bo'lsa — bu token chiqarishdagi bug, so'rov
        // xatosi emas; shuning uchun istisno.
        return raw is not null
               && int.TryParse(raw, CultureInfo.InvariantCulture, out var value)
            ? value
            : throw new InvalidOperationException(
                $"Tokenda '{claimType}' claim'i yo'q yoki noto'g'ri.");
    }
}
