using AccessServer.Application.Common;

namespace AccessServer.Api.Common;

public static class ResultExtensions
{
    /// <summary>
    /// Xato kodini HTTP statusiga bir joyda xaritalaydi — har bir endpoint'da
    /// takrorlanmasligi uchun. Kod noma'lum bo'lsa 400 qaytariladi: bu
    /// klientga "so'rovingda muammo" deyishning xavfsiz zaxira varianti.
    /// </summary>
    public static IResult ToProblem(this Error error) => error.Code switch
    {
        "INVALID_CREDENTIALS" or "ACCOUNT_SUSPENDED" or "OAUTH_NOT_AUTHENTICATED" =>
            Results.Json(ErrorBody(error), statusCode: StatusCodes.Status401Unauthorized),

        "EMAIL_TAKEN" or "SUBDOMAIN_TAKEN"
            or "SUBDOMAIN_QUOTA_EXCEEDED" =>
            Results.Json(ErrorBody(error), statusCode: StatusCodes.Status409Conflict),

        "TOKEN_NOT_FOUND" or "SUBDOMAIN_NOT_FOUND" or "VERIFICATION_TOKEN_INVALID"
            or "OAUTH_PROVIDER_UNKNOWN" =>
            Results.Json(ErrorBody(error), statusCode: StatusCodes.Status404NotFound),

        _ => Results.Json(ErrorBody(error), statusCode: StatusCodes.Status400BadRequest),
    };

    private static object ErrorBody(Error error) =>
        new { code = error.Code, message = error.Message };
}
