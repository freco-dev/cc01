using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AccessServer.Infrastructure.Auth.OAuth;

public static class OAuthRegistration
{
    /// <summary>
    /// Sozlangan OAuth provayderlarini ro'yxatga oladi va qaysilari
    /// yoqilganini qaytaradi.
    ///
    /// Sozlanmagan provayder uchun sxema YARATILMAYDI. Buni kechiktirib
    /// bo'lmaydi: bo'sh `ClientId` bilan ro'yxatga olingan sxema har bir
    /// so'rovda `ArgumentException` tashlaydi — hatto /livez ham 500
    /// qaytaradi. Ya'ni "qaysi sxema mavjud" — startup qarori.
    ///
    /// Sozlamalarning QIYMATLARI esa (masalan JWT imzolash kaliti) so'rov
    /// paytida o'qilishi kerak — u boshqa masala, DEV_SPEC §6.5 A-S14.
    /// </summary>
    public static OAuthProvidersOptions AddAccessOAuth(
        this AuthenticationBuilder authentication,
        IConfiguration configuration)
    {
        var options = configuration.GetSection(OAuthProvidersOptions.SectionName)
            .Get<OAuthProvidersOptions>() ?? new OAuthProvidersOptions();

        authentication.AddCookie(OAuthSchemes.External, cookie =>
        {
            cookie.Cookie.Name = "cc01.external";
            cookie.Cookie.HttpOnly = true;
            cookie.Cookie.IsEssential = true;

            // Provayder bizga TOP-LEVEL redirect bilan qaytadi, shuning uchun
            // Lax yetarli va None dan xavfsizroq.
            cookie.Cookie.SameSite = SameSiteMode.Lax;
            cookie.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;

            // Bu sessiya emas — bir marta o'qiladigan vaqtinchalik holat.
            cookie.ExpireTimeSpan = TimeSpan.FromMinutes(10);
            cookie.SlidingExpiration = false;
        });

        if (options.Github.IsConfigured)
        {
            authentication.AddOAuth(OAuthSchemes.Github, ConfigureGithub(options.Github));
        }

        if (options.Google.IsConfigured)
        {
            authentication.AddGoogle(OAuthSchemes.Google, ConfigureGoogle(options.Google));
        }

        return options;
    }

    private static Action<GoogleOptions> ConfigureGoogle(OAuthProviderOptions provider) => google =>
    {
        google.ClientId = provider.ClientId;
        google.ClientSecret = provider.ClientSecret;
        google.SignInScheme = OAuthSchemes.External;
        google.CallbackPath = "/v1/auth/oauth/google/callback";

        // PKCE: kod ushlab qolinsa ham `code_verifier`siz ishlatib bo'lmaydi.
        google.UsePkce = true;

        google.Scope.Add("openid");
        google.Scope.Add("email");
        google.Scope.Add("profile");

        // Google `email_verified` ni qo'shimcha beradi — hisobga bog'lash
        // qarori aynan shunga tayanadi.
        google.ClaimActions.MapJsonKey("google:email_verified", "email_verified");

        google.SaveTokens = false;   // provayder tokeni bizga kerak emas
    };

    private static Action<OAuthOptions> ConfigureGithub(OAuthProviderOptions provider) => github =>
    {
        github.ClientId = provider.ClientId;
        github.ClientSecret = provider.ClientSecret;
        github.SignInScheme = OAuthSchemes.External;
        github.CallbackPath = "/v1/auth/oauth/github/callback";

        github.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        github.TokenEndpoint = "https://github.com/login/oauth/access_token";
        github.UserInformationEndpoint = "https://api.github.com/user";

        // GitHub S256 PKCE'ni qo'llab-quvvatlaydi (`plain` esa yo'q).
        github.UsePkce = true;

        // `user:email` kerak: profildagi email yopiq bo'lsa /user null
        // qaytaradi va biz uni /user/emails dan olamiz.
        github.Scope.Add("read:user");
        github.Scope.Add("user:email");

        github.SaveTokens = false;

        github.Events = new OAuthEvents
        {
            OnCreatingTicket = async context =>
            {
                var identity = (ClaimsIdentity)context.Principal!.Identity!;

                using var userJson = await GetJsonAsync(
                    context, context.Options.UserInformationEndpoint);

                var root = userJson.RootElement;

                AddClaim(identity, GithubClaims.Id, root.TryGetProperty("id", out var id)
                    ? id.ToString()
                    : null);
                AddClaim(identity, GithubClaims.Login, ReadString(root, "login"));
                AddClaim(identity, GithubClaims.Name, ReadString(root, "name"));

                var (email, verified) = await ResolveEmailAsync(context, root);
                AddClaim(identity, GithubClaims.Email, email);
                AddClaim(identity, GithubClaims.EmailVerified, verified ? "true" : "false");
            },
        };
    };

    /// <summary>
    /// GitHub'da profil emaili yopiq bo'lishi mumkin. Bunday holatda
    /// /user/emails dan **birlamchi va tasdiqlangan** manzil olinadi.
    /// Tasdiqlanmagan emailni qaytarish xavfli — u hisobni egallashga yo'l
    /// ochadi, shuning uchun `verified` bayrog'i ham uzatiladi.
    /// </summary>
    private static async Task<(string? Email, bool Verified)> ResolveEmailAsync(
        OAuthCreatingTicketContext context,
        JsonElement userRoot)
    {
        using var emailsJson = await GetJsonAsync(context, "https://api.github.com/user/emails");

        foreach (var entry in emailsJson.RootElement.EnumerateArray())
        {
            if (entry.TryGetProperty("primary", out var primary) && primary.GetBoolean()
                && entry.TryGetProperty("verified", out var verified) && verified.GetBoolean())
            {
                return (ReadString(entry, "email"), true);
            }
        }

        // Birlamchi tasdiqlangan email topilmadi. Profildagi ochiq emailni
        // qaytaramiz, lekin TASDIQLANMAGAN deb belgilaymiz.
        return (ReadString(userRoot, "email"), false);
    }

    private static async Task<JsonDocument> GetJsonAsync(
        OAuthCreatingTicketContext context,
        string endpoint)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
        request.Headers.UserAgent.ParseAdd("cc01-access-server");

        using var response = await context.Backchannel.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);

        response.EnsureSuccessStatusCode();

        return JsonDocument.Parse(
            await response.Content.ReadAsStringAsync(context.HttpContext.RequestAborted));
    }

    private static string? ReadString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static void AddClaim(ClaimsIdentity identity, string type, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            identity.AddClaim(new Claim(type, value));
        }
    }
}
