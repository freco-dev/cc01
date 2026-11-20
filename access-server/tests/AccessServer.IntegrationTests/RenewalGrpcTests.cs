using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using AccessServer.Api.Grpc;
using AccessServer.Application.Auth;
using AccessServer.Application.Tokens;
using AccessServer.Application.Tunnels;
using AccessServer.Infrastructure.Persistence;
using Cc01.V1;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>
/// `renewal = 7` proto maydoni simdan o'tib handler'gacha yetishi — haqiqiy
/// Kestrel'ning ichki listener'i orqali (qarang <see cref="KestrelAccessApi"/>).
/// Handler darajasidagi semantika <see cref="AuthorizeTunnelTests"/> da.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class RenewalGrpcTests(PostgresFixture fixture) : IAsyncLifetime
{
    private const string Password = "correct horse battery staple";

    private KestrelAccessApi _api = null!;

    public Task InitializeAsync()
    {
        _api = KestrelAccessApi.Start(fixture.ConnectionString, adminKey: null);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    private sealed record Account(int TenantId, string Token);

    private static string UniqueName() => "rg" + Guid.NewGuid().ToString("n")[..10];

    /// <summary>Hisob fixture DI'si orqali — Kestrel'dagi AP ham aynan shu bazada.</summary>
    private async Task<Account> CreateAccountWithTokenAsync()
    {
        await using var scope = fixture.CreateScope();
        var email = $"rg{Guid.NewGuid():n}@example.com";

        var registered = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("A", email, Password, false));

        await scope.ServiceProvider.GetRequiredService<VerifyEmailHandler>()
            .HandleAsync(new VerifyEmailCommand(fixture.Emails.TokenFor(email)));

        var token = await scope.ServiceProvider.GetRequiredService<CreateApiTokenHandler>()
            .HandleAsync(new CreateApiTokenCommand(registered.Value.UserId, "cli", null));

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tenantId = await db.Users.Where(u => u.Id == registered.Value.UserId).Select(u => u.TenantId).SingleAsync();

        return new Account(tenantId, token.Value.Secret);
    }

    /// <summary>gRPC unary chaqiruv qo'lda: 1 bayt siqish bayrog'i + 4 bayt uzunlik (big-endian) + protobuf.</summary>
    private async Task<AuthorizeTunnelResponse> AuthorizeAsync(AuthorizeTunnelRequest message)
    {
        var payload = message.ToByteArray();
        var framed = new byte[5 + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed.AsSpan(1, 4), (uint)payload.Length);
        payload.CopyTo(framed, 5);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/cc01.v1.AccessInternalService/AuthorizeTunnel")
        {
            Content = new ByteArrayContent(framed),
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
        request.Headers.TE.Add(new TransferCodingWithQualityHeaderValue("trailers"));

        using var response = await _api.Internal.SendAsync(request);
        var bytes = await response.Content.ReadAsByteArrayAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("0", response.TrailingHeaders.GetValues("grpc-status").Single());

        return AuthorizeTunnelResponse.Parser.ParseFrom(bytes.AsSpan(5).ToArray());
    }

    private async Task<bool> SubdomainExistsAsync(string name)
    {
        await using var scope = fixture.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AccessDbContext>().Subdomains
            .AnyAsync(s => s.Name == name);
    }

    [Fact]
    public async Task Grpc_renewal_of_unknown_name_is_denied_and_reserves_nothing()
    {
        var account = await CreateAccountWithTokenAsync();
        var name = UniqueName();

        var reply = await AuthorizeAsync(new AuthorizeTunnelRequest
        {
            Token = account.Token,
            Protocol = Protocol.Http,
            Subdomain = name,
            Renewal = true,
        });

        Assert.Equal(AuthorizeTunnelResponse.ResultOneofCase.Denial, reply.ResultCase);
        Assert.Equal(DenialCode.SubdomainNotOwned, reply.Denial.Code);
        Assert.False(await SubdomainExistsAsync(name));
    }

    [Fact]
    public async Task Grpc_open_then_renewal_grants_same_name()
    {
        var account = await CreateAccountWithTokenAsync();
        var name = UniqueName();

        // Eski edge: `renewal` maydoni yo'q — oddiy ochilish, nom band qilinadi.
        var opened = await AuthorizeAsync(new AuthorizeTunnelRequest
        {
            Token = account.Token,
            Protocol = Protocol.Http,
            Subdomain = name,
        });
        Assert.Equal(AuthorizeTunnelResponse.ResultOneofCase.Grant, opened.ResultCase);
        Assert.True(await SubdomainExistsAsync(name));

        var renewed = await AuthorizeAsync(new AuthorizeTunnelRequest
        {
            Token = account.Token,
            Protocol = Protocol.Http,
            Subdomain = opened.Grant.Subdomain,
            Renewal = true,
        });

        Assert.Equal(AuthorizeTunnelResponse.ResultOneofCase.Grant, renewed.ResultCase);
        Assert.Equal(name, renewed.Grant.Subdomain);
        Assert.Equal("free", renewed.Grant.Plan);
        Assert.Equal(24u, renewed.Grant.Limits.MaxConnsPerTunnel);
        Assert.Equal((uint)AuthorizeTunnelHandler.LeaseTtlSeconds, renewed.Grant.LeaseTtlS);
    }

    // ───────────────────────────── Log darajalari ─────────────────────────────

    private async Task<(AuthorizeTunnelResponse Reply, IReadOnlyList<CapturingLogger.Entry> Logs)> InvokeServiceAsync(
        AuthorizeTunnelRequest request)
    {
        await using var scope = fixture.CreateScope();
        var logger = new CapturingLogger();
        var service = new TunnelAuthorizationService(
            scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>(),
            scope.ServiceProvider.GetRequiredService<Application.Usage.RecordUsageHandler>(),
            logger);

        var reply = await service.AuthorizeTunnel(request, new TestServerCallContext());
        return (reply, logger.Entries);
    }

    [Fact]
    public async Task Renewal_grant_is_logged_at_debug()
    {
        var account = await CreateAccountWithTokenAsync();
        var name = UniqueName();

        var (opened, openLogs) = await InvokeServiceAsync(
            new AuthorizeTunnelRequest { Token = account.Token, Subdomain = name });
        Assert.Equal(AuthorizeTunnelResponse.ResultOneofCase.Grant, opened.ResultCase);
        Assert.Empty(openLogs);

        var (renewed, logs) = await InvokeServiceAsync(
            new AuthorizeTunnelRequest { Token = account.Token, Subdomain = name, Renewal = true });

        Assert.Equal(AuthorizeTunnelResponse.ResultOneofCase.Grant, renewed.ResultCase);
        var entry = Assert.Single(logs);
        Assert.Equal(LogLevel.Debug, entry.Level);
        Assert.Contains("renewal=true", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(account.Token, entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Renewal_denial_is_logged_at_information_with_renewal_flag()
    {
        var account = await CreateAccountWithTokenAsync();

        var (reply, logs) = await InvokeServiceAsync(
            new AuthorizeTunnelRequest { Token = account.Token, Subdomain = UniqueName(), Renewal = true });

        Assert.Equal(DenialCode.SubdomainNotOwned, reply.Denial.Code);
        var entry = Assert.Single(logs);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Equal(true, entry.State["Renewal"]);
        Assert.Contains("renewal=True", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(account.Token, entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Open_denial_is_logged_with_renewal_false()
    {
        var (reply, logs) = await InvokeServiceAsync(
            new AuthorizeTunnelRequest { Token = "cc01_invalid", Subdomain = UniqueName() });

        Assert.Equal(DenialCode.TokenInvalid, reply.Denial.Code);
        var entry = Assert.Single(logs);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Equal(false, entry.State["Renewal"]);
    }

    private sealed class CapturingLogger : ILogger<TunnelAuthorizationService>
    {
        public sealed record Entry(LogLevel Level, string Message, IReadOnlyDictionary<string, object?> State);

        private readonly List<Entry> _entries = [];

        public IReadOnlyList<Entry> Entries => _entries;

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var values = state is IEnumerable<KeyValuePair<string, object?>> pairs
                ? pairs.ToDictionary(p => p.Key, p => p.Value)
                : [];

            _entries.Add(new Entry(logLevel, formatter(state, exception), values));
        }
    }

    /// <summary>Servisni gRPC stack'siz chaqirish uchun minimal kontekst.</summary>
    private sealed class TestServerCallContext : ServerCallContext
    {
        protected override string MethodCore => "/cc01.v1.AccessInternalService/AuthorizeTunnel";

        protected override string HostCore => "127.0.0.1";

        protected override string PeerCore => "ipv4:127.0.0.1:0";

        protected override DateTime DeadlineCore => DateTime.MaxValue;

        protected override Metadata RequestHeadersCore { get; } = [];

        protected override CancellationToken CancellationTokenCore => CancellationToken.None;

        protected override Metadata ResponseTrailersCore { get; } = [];

        protected override Status StatusCore { get; set; }

        protected override WriteOptions? WriteOptionsCore { get; set; }

        protected override AuthContext AuthContextCore =>
            new(null, new Dictionary<string, List<AuthProperty>>());

        protected override ContextPropagationToken CreatePropagationTokenCore(ContextPropagationOptions? options) =>
            throw new NotSupportedException();

        protected override Task WriteResponseHeadersAsyncCore(Metadata responseHeaders) => Task.CompletedTask;
    }
}
