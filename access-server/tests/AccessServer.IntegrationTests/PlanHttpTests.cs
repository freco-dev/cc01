using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AccessServer.Api.Common;
using AccessServer.Api.Endpoints;
using Cc01.V1;
using Google.Protobuf;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>
/// GET /v1/plan va ichki operator API — haqiqiy Kestrel ustida (qarang
/// <see cref="KestrelAccessApi"/>): ichki listener himoyasi socket portiga
/// tayanadi, TestServer'da esa u doim 0.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class PlanHttpTests(PostgresFixture fixture) : IAsyncLifetime
{
    private const string Password = "correct horse battery staple";
    private const string AdminKey = "test-key";

    private KestrelAccessApi _api = null!;

    public Task InitializeAsync()
    {
        _api = KestrelAccessApi.Start(fixture.ConnectionString, AdminKey);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private sealed record Session(string Jwt, string Slug);

    private async Task<Session> RegisterVerifyAndLoginAsync()
    {
        var email = $"ph{Guid.NewGuid():n}@example.com";

        var register = await _api.Public.PostAsJsonAsync("/v1/auth/register", new
        {
            fullName = "Aziz Karimov",
            email,
            password = Password,
            subscribe = false,
        });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        // Slug register javobidagi Location'dan: /v1/tenants/{slug}.
        var slug = register.Headers.Location!.OriginalString.Split('/')[^1];

        var verify = await _api.Public.PostAsJsonAsync("/v1/auth/verify-email",
            new { token = _api.Emails.TokenFor(email) });
        Assert.Equal(HttpStatusCode.NoContent, verify.StatusCode);

        var login = await _api.Public.PostAsJsonAsync("/v1/auth/login", new { email, password = Password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);

        var jwt = (await BodyAsync(login)).GetProperty("accessToken").GetString()!;
        return new Session(jwt, slug);
    }

    private async Task<JsonElement> GetPlanAsync(string jwt)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/plan");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        using var response = await _api.Public.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await BodyAsync(response);
    }

    /// <summary>
    /// Sukut bo'yicha HTTP/2 (ichki listener faqat h2c). Public listener esa
    /// TLS'siz faqat HTTP/1.1 — soxtalashtirish testlari <paramref name="version"/>
    /// ni 1.1 qilib beradi. (HttpClient.DefaultRequestVersion qo'lda
    /// yaratilgan HttpRequestMessage'ga ta'sir qilmaydi.)
    /// </summary>
    private static HttpRequestMessage ChangePlanRequest(
        string slug,
        object body,
        string? adminKey = AdminKey,
        string? actor = "aziz",
        Version? version = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Put, $"/internal/v1/tenants/{slug}/subscription")
        {
            Content = JsonContent.Create(body),
            Version = version ?? HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };

        if (adminKey is not null)
        {
            request.Headers.Add(AdminKeyFilter.HeaderName, adminKey);
        }

        if (actor is not null)
        {
            request.Headers.Add("X-Cc01-Actor", actor);
        }

        return request;
    }

    /// <summary>gRPC so'rovi qo'lda: 1 bayt siqish bayrog'i + 4 bayt uzunlik (big-endian) + protobuf.</summary>
    private static HttpRequestMessage GrpcAuthorizeRequest(Version version)
    {
        var payload = new AuthorizeTunnelRequest { Token = "cc01_invalid", Subdomain = "spoofed" }.ToByteArray();
        var framed = new byte[5 + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed.AsSpan(1, 4), (uint)payload.Length);
        payload.CopyTo(framed, 5);

        var request = new HttpRequestMessage(HttpMethod.Post, "/cc01.v1.AccessInternalService/AuthorizeTunnel")
        {
            Content = new ByteArrayContent(framed),
            Version = version,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
        request.Headers.TE.Add(new TransferCodingWithQualityHeaderValue("trailers"));
        return request;
    }

    [Fact]
    public async Task Get_plan_requires_jwt()
    {
        var response = await _api.Public.GetAsync("/v1/plan");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Get_plan_returns_free_limits_after_register()
    {
        var session = await RegisterVerifyAndLoginAsync();

        var plan = await GetPlanAsync(session.Jwt);

        Assert.Equal("free", plan.GetProperty("plan").GetString());
        Assert.Equal("Subscription", plan.GetProperty("source").GetString());
        Assert.Equal("Active", plan.GetProperty("subscription").GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, plan.GetProperty("subscription").GetProperty("periodEnd").ValueKind);

        var limits = plan.GetProperty("limits");
        Assert.Equal(24, limits.GetProperty("maxConnsPerTunnel").GetInt32());
        Assert.Equal(1, limits.GetProperty("maxSubdomains").GetInt32());
        Assert.Equal(1, limits.GetProperty("maxTunnels").GetInt32());
        Assert.Equal(100_000_000, limits.GetProperty("bandwidthBps").GetInt64());

        Assert.Equal(0, plan.GetProperty("usage").GetProperty("subdomains").GetInt32());
    }

    [Fact]
    public async Task Internal_change_then_get_plan_shows_pro()
    {
        var session = await RegisterVerifyAndLoginAsync();
        var periodEnd = DateTimeOffset.UtcNow.AddDays(30);

        using var request = ChangePlanRequest(session.Slug, new { plan = "pro", periodEnd, reason = "sinov" });
        using var response = await _api.Internal.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await BodyAsync(response);
        Assert.Equal(session.Slug, body.GetProperty("tenant").GetString());
        Assert.Equal("pro", body.GetProperty("plan").GetString());
        Assert.Equal("Active", body.GetProperty("status").GetString());
        Assert.True(body.GetProperty("changed").GetBoolean());

        var plan = await GetPlanAsync(session.Jwt);
        Assert.Equal("pro", plan.GetProperty("plan").GetString());
        Assert.Equal(128, plan.GetProperty("limits").GetProperty("maxConnsPerTunnel").GetInt32());
        Assert.NotEqual(JsonValueKind.Null, plan.GetProperty("subscription").GetProperty("periodEnd").ValueKind);

        // Takror — o'zgarish yo'q.
        using var again = ChangePlanRequest(session.Slug, new { plan = "pro", periodEnd, reason = "sinov" });
        using var againResponse = await _api.Internal.SendAsync(again);
        Assert.False((await BodyAsync(againResponse)).GetProperty("changed").GetBoolean());
    }

    [Fact]
    public async Task Internal_plan_change_with_spoofed_host_on_public_port_returns_404()
    {
        var session = await RegisterVerifyAndLoginAsync();

        // Host sarlavhasi ichki portni ko'rsatadi — RequireHost aldanadi,
        // lekin socket public portniki.
        using var spoofed = ChangePlanRequest(
            session.Slug, new { plan = "enterprise" }, version: HttpVersion.Version11);
        spoofed.Headers.Host = $"127.0.0.1:{_api.InternalPort}";
        using var response = await _api.Public.SendAsync(spoofed);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        // Soxtalashtirilmagan holda ham public portda yo'q.
        using var plain = ChangePlanRequest(
            session.Slug, new { plan = "enterprise" }, version: HttpVersion.Version11);
        Assert.Equal(HttpStatusCode.NotFound, (await _api.Public.SendAsync(plain)).StatusCode);

        // Tarif o'zgarmadi.
        var plan = await GetPlanAsync(session.Jwt);
        Assert.Equal("free", plan.GetProperty("plan").GetString());
    }

    [Fact]
    public async Task Grpc_on_internal_port_is_served()
    {
        // Ijobiy nazorat: servis ichki portda haqiqatan ishlaydi — aks holda
        // quyidagi 404 testi hech narsani isbotlamasdi.
        using var request = GrpcAuthorizeRequest(HttpVersion.Version20);
        using var response = await _api.Internal.SendAsync(request);
        var bytes = await response.Content.ReadAsByteArrayAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("0", response.TrailingHeaders.GetValues("grpc-status").Single());

        var reply = AuthorizeTunnelResponse.Parser.ParseFrom(bytes.AsSpan(5).ToArray());
        Assert.Equal(DenialCode.TokenInvalid, reply.Denial.Code);
    }

    [Fact]
    public async Task Grpc_on_public_port_with_spoofed_host_is_rejected()
    {
        using var request = GrpcAuthorizeRequest(HttpVersion.Version11);
        request.Headers.Host = $"127.0.0.1:{_api.InternalPort}";

        using var response = await _api.Public.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.False(response.Headers.Contains("grpc-status"));
        Assert.False(response.TrailingHeaders.Contains("grpc-status"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("wrong")]
    [InlineData("test-key ")]
    [InlineData("TEST-KEY")]
    public async Task Missing_or_wrong_admin_key_returns_401_ADMIN_KEY_INVALID(string? key)
    {
        var session = await RegisterVerifyAndLoginAsync();

        using var request = ChangePlanRequest(session.Slug, new { plan = "pro" }, adminKey: key);
        using var response = await _api.Internal.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("ADMIN_KEY_INVALID", (await BodyAsync(response)).GetProperty("code").GetString());

        var plan = await GetPlanAsync(session.Jwt);
        Assert.Equal("free", plan.GetProperty("plan").GetString());
    }

    /// <summary>
    /// Deny-by-default: kalit sozlanmagan bo'lsa yo'l UMUMAN yo'q. Haqiqiy
    /// tenant bilan tekshiriladi — aks holda "kalitsiz ochiq" regressiya ham
    /// TENANT_NOT_FOUND (404) qaytarib, testdan o'tib ketardi.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData(AdminKey)]
    public async Task Internal_route_absent_when_admin_key_unset(string? sentKey)
    {
        await using var api = KestrelAccessApi.Start(fixture.ConnectionString, adminKey: null);
        var session = await RegisterVerifyAndLoginAsync();

        using var request = ChangePlanRequest(session.Slug, new { plan = "enterprise" }, adminKey: sentKey);
        using var response = await api.Internal.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        // Routing'dagi 404 — tanasiz; handler'ning TENANT_NOT_FOUND'i emas.
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("TENANT_NOT_FOUND", body, StringComparison.Ordinal);
        Assert.DoesNotContain("\"code\"", body, StringComparison.Ordinal);

        // Tarif o'zgarmadi.
        var plan = await GetPlanAsync(session.Jwt);
        Assert.Equal("free", plan.GetProperty("plan").GetString());
    }

    [Fact]
    public async Task Openapi_document_does_not_describe_internal_endpoints()
    {
        // Development'da /openapi/v1.json public portda ochiq. Ichki
        // endpointlar u yerda ko'rinmasligi kerak (A-S19: mavjudligini ham
        // oshkor qilmaymiz).
        using var response = await _api.Public.GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var document = await response.Content.ReadAsStringAsync();

        // Ijobiy nazorat: hujjat haqiqatan endpointlarni sanaydi.
        Assert.Contains("/v1/plan", document, StringComparison.Ordinal);

        Assert.DoesNotContain("/internal/", document, StringComparison.Ordinal);
        Assert.DoesNotContain(InternalPlanEndpoints.ActorHeader, document, StringComparison.Ordinal);
        Assert.DoesNotContain("AccessInternalService", document, StringComparison.Ordinal);
    }

    [Fact]
    public void Startup_fails_when_public_and_internal_ports_are_equal()
    {
        var settings = new Dictionary<string, string?>
        {
            ["Public:Address"] = "127.0.0.1",
            ["Public:Port"] = "5099",
            ["Internal:Address"] = "127.0.0.1",
            ["Internal:Port"] = "5099",
            ["Internal:AdminKey"] = AdminKey,
        };

        using var factory = new AccessApiFactory(fixture.ConnectionString, settings);
        factory.UseKestrel();

        var error = Assert.ThrowsAny<Exception>(factory.StartServer);

        // Bind xatosi emas (u ham bir xil IP'da yiqilardi) — aynan bizning
        // tekshiruv: turli IP'larda bind muvaffaqiyatli bo'lardi.
        var messages = string.Join(" | ", Flatten(error).Select(e => e.Message));
        Assert.Contains("Public:Port va Internal:Port bir xil", messages, StringComparison.Ordinal);
    }

    private static IEnumerable<Exception> Flatten(Exception error)
    {
        for (var e = error; e is not null; e = e.InnerException)
        {
            yield return e;
        }
    }

    [Fact]
    public async Task Missing_actor_returns_400()
    {
        var session = await RegisterVerifyAndLoginAsync();

        using var request = ChangePlanRequest(session.Slug, new { plan = "pro" }, actor: null);
        using var response = await _api.Internal.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("PLAN_ACTOR_INVALID", (await BodyAsync(response)).GetProperty("code").GetString());
    }

    [Fact]
    public async Task Unknown_plan_returns_400_PLAN_UNKNOWN()
    {
        var session = await RegisterVerifyAndLoginAsync();

        using var request = ChangePlanRequest(session.Slug, new { plan = "1" });
        using var response = await _api.Internal.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("PLAN_UNKNOWN", (await BodyAsync(response)).GetProperty("code").GetString());
    }

    [Fact]
    public async Task Unknown_tenant_returns_404()
    {
        using var request = ChangePlanRequest("t_doesnotexist", new { plan = "pro" });
        using var response = await _api.Internal.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("TENANT_NOT_FOUND", (await BodyAsync(response)).GetProperty("code").GetString());
    }
}

/// <summary>
/// Guard middleware'ning o'zi — Kestrel'siz. Guard port raqamiga emas,
/// ichki listener qo'ygan ulanish belgisiga qaraydi.
/// </summary>
public sealed class InternalListenerGuardTests
{
    private const int InternalPort = 5081;

    private sealed class ConnectionItems : IConnectionItemsFeature
    {
        public IDictionary<object, object?> Items { get; set; } = new Dictionary<object, object?>();
    }

    private static async Task<(int Status, bool NextCalled)> InvokeAsync(
        int localPort, bool internalOnly, bool markedInternal, bool withItemsFeature = true)
    {
        var context = new DefaultHttpContext();
        context.Connection.LocalPort = localPort;

        if (withItemsFeature)
        {
            var items = new ConnectionItems();
            if (markedInternal)
            {
                InternalListenerExtensions.MarkInternal(items.Items);
            }

            context.Features.Set<IConnectionItemsFeature>(items);
        }

        context.SetEndpoint(new Endpoint(
            _ => Task.CompletedTask,
            internalOnly
                ? new EndpointMetadataCollection(new InternalOnlyMetadata())
                : EndpointMetadataCollection.Empty,
            "test"));

        var nextCalled = false;
        var middleware = new InternalListenerGuardMiddleware(
            _ =>
            {
                nextCalled = true;
                return Task.CompletedTask;
            },
            NullLogger<InternalListenerGuardMiddleware>.Instance);

        await middleware.InvokeAsync(context);
        return (context.Response.StatusCode, nextCalled);
    }

    [Theory]
    [InlineData(5078)]
    [InlineData(0)] // TestServer
    public async Task Internal_endpoint_on_unmarked_connection_is_404(int localPort)
    {
        var (status, nextCalled) = await InvokeAsync(localPort, internalOnly: true, markedInternal: false);

        Assert.Equal(StatusCodes.Status404NotFound, status);
        Assert.False(nextCalled);
    }

    /// <summary>
    /// Public listener ichki bilan BIR XIL portda (boshqa IP'da): LocalPort mos
    /// keladi, lekin ulanishni public listener qabul qilgan — o'tkazilmaydi.
    /// Port bo'yicha tekshiruv buni o'tkazib yuborardi.
    /// </summary>
    [Fact]
    public async Task Internal_endpoint_on_public_listener_with_same_port_is_404()
    {
        var (status, nextCalled) = await InvokeAsync(InternalPort, internalOnly: true, markedInternal: false);

        Assert.Equal(StatusCodes.Status404NotFound, status);
        Assert.False(nextCalled);
    }

    [Fact]
    public async Task Internal_endpoint_without_connection_items_is_404()
    {
        var (status, nextCalled) = await InvokeAsync(
            InternalPort, internalOnly: true, markedInternal: false, withItemsFeature: false);

        Assert.Equal(StatusCodes.Status404NotFound, status);
        Assert.False(nextCalled);
    }

    [Fact]
    public async Task Internal_endpoint_on_marked_connection_passes()
    {
        var (_, nextCalled) = await InvokeAsync(InternalPort, internalOnly: true, markedInternal: true);
        Assert.True(nextCalled);
    }

    [Fact]
    public async Task Public_endpoint_is_untouched()
    {
        var (_, nextCalled) = await InvokeAsync(5078, internalOnly: false, markedInternal: false);
        Assert.True(nextCalled);
    }
}
