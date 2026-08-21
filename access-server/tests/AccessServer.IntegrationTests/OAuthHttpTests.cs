using System.Net;
using System.Text.Json;
using System.Web;
using Xunit;

namespace AccessServer.IntegrationTests;

[Collection(PostgresCollection.Name)]
public sealed class OAuthHttpTests(PostgresFixture fixture)
{
    /// <summary>
    /// Provayder sirlari — soxta, lekin sxema ro'yxatga olinishi uchun
    /// yetarli. Haqiqiy tarmoq chaqiruvi bo'lmaydi: biz faqat provayderga
    /// yo'naltirishni tekshiramiz.
    /// </summary>
    private static Dictionary<string, string?> ConfiguredProviders() => new()
    {
        ["OAuth:Github:ClientId"] = "test-github-client",
        ["OAuth:Github:ClientSecret"] = "test-github-secret",
        ["OAuth:Google:ClientId"] = "test-google-client",
        ["OAuth:Google:ClientSecret"] = "test-google-secret",
    };

    private HttpClient CreateClient(IDictionary<string, string?>? config, out AccessApiFactory factory)
    {
        factory = new AccessApiFactory(fixture.ConnectionString, config);

        // Redirect'ni kuzatmaymiz: bizni provayderga ketayotgan manzilning
        // O'ZI qiziqtiradi, uning javobi emas.
        return factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });
    }

    [Fact]
    public async Task Unknown_provider_returns_404()
    {
        using var client = CreateClient(ConfiguredProviders(), out var factory);
        using (factory)
        {
            var response = await client.GetAsync("/v1/auth/oauth/facebook");

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal("OAUTH_PROVIDER_UNKNOWN", await CodeAsync(response));
        }
    }

    [Fact]
    public async Task Unconfigured_provider_returns_clear_error_not_500()
    {
        // Sirlarsiz: sxema ro'yxatga olinmagan. Challenge chaqirilsa istisno
        // bo'lardi — endpoint buni oldindan tekshirishi kerak.
        using var client = CreateClient(config: null, out var factory);
        using (factory)
        {
            var response = await client.GetAsync("/v1/auth/oauth/github");

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("OAUTH_PROVIDER_NOT_CONFIGURED", await CodeAsync(response));
        }
    }

    [Fact]
    public async Task Complete_without_provider_session_returns_401()
    {
        using var client = CreateClient(ConfiguredProviders(), out var factory);
        using (factory)
        {
            var response = await client.GetAsync("/v1/auth/oauth/complete");

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal("OAUTH_NOT_AUTHENTICATED", await CodeAsync(response));
        }
    }

    [Theory]
    [InlineData("github", "github.com", "read:user user:email")]
    [InlineData("google", "accounts.google.com", "openid email profile")]
    public async Task Challenge_redirects_with_state_and_pkce(
        string provider, string expectedHost, string expectedScopes)
    {
        using var client = CreateClient(ConfiguredProviders(), out var factory);
        using (factory)
        {
            var response = await client.GetAsync($"/v1/auth/oauth/{provider}");

            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);

            var location = response.Headers.Location!;
            Assert.Equal(expectedHost, location.Host);

            var query = HttpUtility.ParseQueryString(location.Query);

            // State — CSRF va sessiyani bog'lash uchun.
            Assert.False(string.IsNullOrEmpty(query["state"]));

            // PKCE: kod ushlab qolinsa ham verifier'siz ishlatib bo'lmaydi.
            Assert.False(string.IsNullOrEmpty(query["code_challenge"]));
            Assert.Equal("S256", query["code_challenge_method"]);

            Assert.Equal("code", query["response_type"]);
            Assert.EndsWith($"/v1/auth/oauth/{provider}/callback", query["redirect_uri"]!,
                StringComparison.Ordinal);

            foreach (var scope in expectedScopes.Split(' '))
            {
                Assert.Contains(scope, query["scope"]!, StringComparison.Ordinal);
            }

            // Korrelyatsiya cookie'si — usiz callback state'ni tekshira olmaydi.
            Assert.Contains(response.Headers.GetValues("Set-Cookie"),
                c => c.Contains(".AspNetCore.Correlation.", StringComparison.Ordinal));
        }
    }

    private static async Task<string?> CodeAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync())
            .RootElement.GetProperty("code").GetString();
}
