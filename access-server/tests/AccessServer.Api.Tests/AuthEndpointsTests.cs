using System.Net;
using System.Net.Http.Json;

namespace AccessServer.Api.Tests;

public sealed class AuthEndpointsTests : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client;

    public AuthEndpointsTests(ApiFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Register_ReturnsCreated()
    {
        var response = await _client.PostAsJsonAsync("/api/auth/register", new
        {
            fullName = "Alice",
            email = "alice@example.com",
            password = "Password123!",
            subscribe = true
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task SignIn_ReturnsOk()
    {
        var response = await _client.PostAsJsonAsync("/api/auth/sign-in", new
        {
            email = "alice@example.com",
            password = "Password123!"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task VerifyEmail_ReturnsOk()
    {
        var response = await _client.PostAsJsonAsync("/api/auth/verify-email", new
        {
            email = "alice@example.com",
            verificationCode = "123456"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_ReturnsOk()
    {
        var response = await _client.PostAsJsonAsync("/api/auth/refresh", new
        {
            email = "alice@example.com",
            refreshToken = "refresh-token"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CheckEmail_ReturnsOk()
    {
        var response = await _client.GetAsync("/api/auth/email-check?email=alice@example.com");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Me_ReturnsOk()
    {
        var response = await _client.GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}