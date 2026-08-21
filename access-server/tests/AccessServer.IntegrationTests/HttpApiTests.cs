using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AccessServer.IntegrationTests;

[Collection(PostgresCollection.Name)]
public sealed class HttpApiTests(PostgresFixture fixture) : IAsyncLifetime
{
    private const string Password = "correct horse battery staple";

    private AccessApiFactory _factory = null!;
    private HttpClient _client = null!;

    public Task InitializeAsync()
    {
        _factory = new AccessApiFactory(fixture.ConnectionString);
        _client = _factory.CreateClient();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _factory.DisposeAsync();
    }

    private static string UniqueEmail() => $"h{Guid.NewGuid():n}@example.com";

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private async Task<string> RegisterVerifyAndLoginAsync()
    {
        var email = UniqueEmail();

        var register = await _client.PostAsJsonAsync("/v1/auth/register", new
        {
            fullName = "Aziz Karimov",
            email,
            password = Password,
            subscribe = false,
        });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var emails = _factory.Services.GetRequiredService<RecordingEmailSender>();
        var verify = await _client.PostAsJsonAsync("/v1/auth/verify-email",
            new { token = emails.TokenFor(email) });
        Assert.Equal(HttpStatusCode.NoContent, verify.StatusCode);

        var login = await _client.PostAsJsonAsync("/v1/auth/login", new { email, password = Password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var body = await BodyAsync(login);
        Assert.True(body.GetProperty("emailVerified").GetBoolean());

        return body.GetProperty("accessToken").GetString()!;
    }

    private void Authorize(string jwt) =>
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

    [Fact]
    public async Task Liveness_and_readiness_are_reachable()
    {
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/livez")).StatusCode);

        // Baza ishlab turibdi, demak readiness ham OK.
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync("/readyz")).StatusCode);
    }

    [Fact]
    public async Task Protected_endpoints_require_authentication()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.GetAsync("/v1/tokens")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.GetAsync("/v1/subdomains")).StatusCode);
    }

    /// <summary>
    /// Regressiya testi: JWT bearer standart holda "sub" claim'ini
    /// ClaimTypes.NameIdentifier ga xaritalaydi va endpoint 500 bilan
    /// yiqiladi. Program.cs dagi MapInboundClaims=false shuni oldini oladi.
    /// </summary>
    [Fact]
    public async Task Jwt_claims_are_readable_by_endpoints()
    {
        Authorize(await RegisterVerifyAndLoginAsync());

        var response = await _client.GetAsync("/v1/tokens");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(JsonValueKind.Array, (await BodyAsync(response)).ValueKind);
    }

    [Fact]
    public async Task Token_creation_returns_secret_once_and_lists_without_it()
    {
        Authorize(await RegisterVerifyAndLoginAsync());

        var created = await _client.PostAsJsonAsync("/v1/tokens", new { name = "laptop" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var body = await BodyAsync(created);
        var secret = body.GetProperty("secret").GetString()!;
        Assert.StartsWith("cc01_live_", secret, StringComparison.Ordinal);

        // Ro'yxatda sir bo'lmasligi kerak — faqat prefiks.
        var listed = await _client.GetAsync("/v1/tokens");
        var raw = await listed.Content.ReadAsStringAsync();
        Assert.DoesNotContain(secret, raw, StringComparison.Ordinal);
        Assert.Contains(body.GetProperty("prefix").GetString()!, raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unverified_email_cannot_create_token()
    {
        var email = UniqueEmail();
        await _client.PostAsJsonAsync("/v1/auth/register",
            new { fullName = "A", email, password = Password, subscribe = false });

        var login = await _client.PostAsJsonAsync("/v1/auth/login", new { email, password = Password });
        Authorize((await BodyAsync(login)).GetProperty("accessToken").GetString()!);

        var response = await _client.PostAsJsonAsync("/v1/tokens", new { name = "laptop" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("EMAIL_NOT_VERIFIED", (await BodyAsync(response)).GetProperty("code").GetString());
    }

    [Theory]
    [InlineData("www", HttpStatusCode.BadRequest, "SUBDOMAIN_RESERVED")]
    [InlineData("ab", HttpStatusCode.BadRequest, "SUBDOMAIN_BAD_LENGTH")]
    [InlineData("-bad", HttpStatusCode.BadRequest, "SUBDOMAIN_BAD_FORMAT")]
    public async Task Invalid_subdomain_maps_to_expected_status(
        string name, HttpStatusCode expectedStatus, string expectedCode)
    {
        Authorize(await RegisterVerifyAndLoginAsync());

        var response = await _client.PostAsJsonAsync("/v1/subdomains", new { name });

        Assert.Equal(expectedStatus, response.StatusCode);
        Assert.Equal(expectedCode, (await BodyAsync(response)).GetProperty("code").GetString());
    }

    [Fact]
    public async Task Subdomain_conflict_across_tenants_returns_409()
    {
        var name = "app" + Guid.NewGuid().ToString("n")[..10];

        Authorize(await RegisterVerifyAndLoginAsync());
        Assert.Equal(HttpStatusCode.Created,
            (await _client.PostAsJsonAsync("/v1/subdomains", new { name })).StatusCode);

        // Boshqa tenant o'sha nomni so'raydi.
        Authorize(await RegisterVerifyAndLoginAsync());
        var response = await _client.PostAsJsonAsync("/v1/subdomains", new { name });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal("SUBDOMAIN_TAKEN", (await BodyAsync(response)).GetProperty("code").GetString());
    }

    [Fact]
    public async Task Duplicate_registration_returns_409()
    {
        var email = UniqueEmail();
        var payload = new { fullName = "A", email, password = Password, subscribe = false };

        Assert.Equal(HttpStatusCode.Created,
            (await _client.PostAsJsonAsync("/v1/auth/register", payload)).StatusCode);

        var second = await _client.PostAsJsonAsync("/v1/auth/register", payload);

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.Equal("EMAIL_TAKEN", (await BodyAsync(second)).GetProperty("code").GetString());
    }

    [Fact]
    public async Task Bad_credentials_return_401()
    {
        var response = await _client.PostAsJsonAsync("/v1/auth/login",
            new { email = UniqueEmail(), password = "definitely wrong password" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("INVALID_CREDENTIALS", (await BodyAsync(response)).GetProperty("code").GetString());
    }
}
