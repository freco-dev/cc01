using System.Security.Claims;
using AccessServer.Api.Common;
using AccessServer.Application.Auth;
using AccessServer.Infrastructure.Auth.OAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.JsonWebTokens;

namespace AccessServer.Api.Endpoints;

public static class OAuthEndpoints
{
    /// <param name="enabled">
    /// Sozlangan provayderlar. Sozlanmagani uchun sxema ro'yxatda yo'q va
    /// Challenge chaqirilsa istisno bo'lardi — oldindan tekshiramiz.
    /// </param>
    public static IEndpointRouteBuilder MapOAuthEndpoints(
        this IEndpointRouteBuilder app,
        OAuthProvidersOptions enabled)
    {
        var group = app.MapGroup("/v1/auth/oauth").WithTags("OAuth");

        group.MapGet("/{provider}", (string provider) =>
        {
            if (!TryResolve(provider, out var parsed, out var scheme))
            {
                return OAuthErrors.ProviderUnknown.ToProblem();
            }

            if (!IsConfigured(enabled, parsed))
            {
                return OAuthErrors.ProviderNotConfigured.ToProblem();
            }

            // Provayder bizni shu manzilga qaytaradi; u yerda External
            // cookie'dan foydalanuvchini o'qib, JWT beramiz.
            var properties = new AuthenticationProperties
            {
                RedirectUri = "/v1/auth/oauth/complete",
            };

            // State va PKCE `code_verifier` ni handler o'zi yaratadi va
            // korrelyatsiya cookie'sida saqlaydi — qo'lda boshqarilmaydi.
            return Results.Challenge(properties, [scheme]);
        })
        .WithSummary("Provayderga yo'naltiradi (state + PKCE handler tomonidan)");

        group.MapGet("/complete", async (
            HttpContext http,
            OAuthLoginHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await http.AuthenticateAsync(OAuthSchemes.External);

            if (!result.Succeeded || result.Principal is null)
            {
                return OAuthErrors.NotAuthenticated.ToProblem();
            }

            // Vaqtinchalik cookie bir marta ishlatiladi — natijadan qat'i
            // nazar darhol o'chiriladi.
            await http.SignOutAsync(OAuthSchemes.External);

            var command = BuildCommand(result.Principal);
            if (command is null)
            {
                return OAuthErrors.SubjectMissing.ToProblem();
            }

            var login = await handler.HandleAsync(command, cancellationToken);

            return login.IsSuccess
                ? Results.Ok(new
                {
                    accessToken = login.Value.AccessToken,
                    expiresAt = login.Value.ExpiresAt,
                    emailVerified = login.Value.EmailVerified,
                    tenantSlug = login.Value.TenantSlug,
                })
                : login.Error!.ToProblem();
        })
        .WithSummary("Provayder qaytargan natijadan JWT beradi");

        return app;
    }

    private static bool TryResolve(string provider, out OAuthProvider parsed, out string scheme)
    {
        switch (provider.ToLowerInvariant())
        {
            case "github":
                parsed = OAuthProvider.Github;
                scheme = OAuthSchemes.Github;
                return true;

            case "google":
                parsed = OAuthProvider.Google;
                scheme = OAuthSchemes.Google;
                return true;

            default:
                parsed = default;
                scheme = string.Empty;
                return false;
        }
    }

    private static bool IsConfigured(OAuthProvidersOptions options, OAuthProvider provider) =>
        provider switch
        {
            OAuthProvider.Github => options.Github.IsConfigured,
            OAuthProvider.Google => options.Google.IsConfigured,
            _ => false,
        };

    /// <summary>
    /// Ikkala provayder claim'larini bitta buyruqqa keltiradi. GitHub uchun
    /// claim nomlari o'zimizniki, Google uchun — standart OIDC nomlari.
    /// </summary>
    private static OAuthLoginCommand? BuildCommand(ClaimsPrincipal principal)
    {
        var githubId = principal.FindFirstValue(GithubClaims.Id);
        if (!string.IsNullOrEmpty(githubId))
        {
            return new OAuthLoginCommand(
                OAuthProvider.Github,
                githubId,
                principal.FindFirstValue(GithubClaims.Email),
                string.Equals(principal.FindFirstValue(GithubClaims.EmailVerified), "true", StringComparison.Ordinal),
                principal.FindFirstValue(GithubClaims.Name)
                    ?? principal.FindFirstValue(GithubClaims.Login));
        }

        // Google handleri `sub` ni NameIdentifier sifatida yozadi.
        var googleId = principal.FindFirstValue(ClaimTypes.NameIdentifier)
                       ?? principal.FindFirstValue(JwtRegisteredClaimNames.Sub);

        if (string.IsNullOrEmpty(googleId))
        {
            return null;
        }

        return new OAuthLoginCommand(
            OAuthProvider.Google,
            googleId,
            principal.FindFirstValue(ClaimTypes.Email),
            string.Equals(principal.FindFirstValue("google:email_verified"), "true", StringComparison.OrdinalIgnoreCase),
            principal.FindFirstValue(ClaimTypes.Name));
    }
}
