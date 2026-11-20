using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using AccessServer.Domain.Entities;
using AccessServer.Infrastructure.Persistence;
using Cc01.V1;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>
/// ReportUsage simdan o'tib bazagacha — haqiqiy Kestrel'ning ichki listener'i
/// orqali: ochiq matnli h2c (ReportedBy = "plaintext") va mTLS (ReportedBy =
/// klient CN). Semantika tafsilotlari <see cref="UsageRecordTests"/> da.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class UsageGrpcTests(PostgresFixture fixture) : IAsyncLifetime
{
    private readonly TestPki _pki = new();

    private KestrelAccessApi _plaintext = null!;
    private KestrelAccessApi _mtls = null!;

    public Task InitializeAsync()
    {
        _plaintext = KestrelAccessApi.Start(fixture.ConnectionString, adminKey: null);

        var server = _pki.IssueServer();
        _mtls = KestrelAccessApi.Start(fixture.ConnectionString, adminKey: null, new Dictionary<string, string?>
        {
            ["Internal:Tls:CertPath"] = server.CertPath,
            ["Internal:Tls:KeyPath"] = server.KeyPath,
            ["Internal:Tls:ClientCaPath"] = _pki.CaPath,
            ["Internal:Tls:AllowedClients"] = "edge-usage-1",
        });

        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _plaintext.DisposeAsync();
        await _mtls.DisposeAsync();
        _pki.Dispose();
    }

    private HttpClient MtlsClient(X509Certificate2 clientCertificate)
    {
        var policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        policy.CustomTrustStore.Add(_pki.Ca);

        return new HttpClient(new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                CertificateChainPolicy = policy,
                LocalCertificateSelectionCallback = (_, _, _, _, _) => clientCertificate,
            },
        })
        {
            BaseAddress = new Uri($"https://127.0.0.1:{_mtls.InternalPort}"),
        };
    }

    private async Task<(string Slug, string Tunnel)> NewTenantAndTunnelAsync()
    {
        await using var scope = fixture.CreateScope();
        var tenant = await UsageTestSupport.CreateTenantAsync(scope.ServiceProvider.GetRequiredService<AccessDbContext>());
        return (tenant.Slug, UsageTestSupport.UniqueTunnel());
    }

    private static ReportUsageRequest Request(string slug, string tunnel, int count)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var request = new ReportUsageRequest();
        for (var i = 0; i < count; i++)
        {
            request.Windows.Add(new UsageWindow
            {
                TenantId = slug,
                TunnelId = tunnel,
                WindowStart = now - 120 - (i * 60),
                WindowEnd = now - 60 - (i * 60),
                BytesIn = 10,
                BytesOut = 20,
                Connections = 1,
            });
        }

        return request;
    }

    private static async Task<(string Status, ReportUsageResponse? Reply)> ReportAsync(
        HttpClient client,
        ReportUsageRequest message)
    {
        using var request = UsageTestSupport.GrpcRequest("ReportUsage", message);
        using var response = await client.SendAsync(request);
        var bytes = await response.Content.ReadAsByteArrayAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var status = UsageTestSupport.GrpcStatus(response);

        return status == "0"
            ? (status, ReportUsageResponse.Parser.ParseFrom(bytes.AsSpan(5).ToArray()))
            : (status, null);
    }

    private async Task<List<UsageRecord>> RowsAsync(string tunnel)
    {
        await using var scope = fixture.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AccessDbContext>().UsageRecords
            .AsNoTracking()
            .Where(u => u.TunnelId == tunnel)
            .ToListAsync();
    }

    [Fact]
    public async Task Plaintext_internal_listener_stores_rows_as_plaintext()
    {
        var (slug, tunnel) = await NewTenantAndTunnelAsync();
        var message = Request(slug, tunnel, count: 3);
        message.Windows.Add(new UsageWindow { TenantId = "t_nope_nope_x", TunnelId = tunnel, WindowStart = 1, WindowEnd = 2 });

        var (status, reply) = await ReportAsync(_plaintext.Internal, message);
        Assert.Equal("0", status);
        Assert.Equal(4u, reply!.Accepted);

        // Edge qayta yuborsa ham — accepted o'sha, qator ko'paymaydi.
        var (_, retry) = await ReportAsync(_plaintext.Internal, message);
        Assert.Equal(4u, retry!.Accepted);

        var rows = await RowsAsync(tunnel);
        Assert.Equal(3, rows.Count);
        Assert.All(rows, r => Assert.Equal(UsageRecord.PlaintextReporter, r.ReportedBy));
    }

    [Fact]
    public async Task Mtls_internal_listener_stores_client_cn_as_reporter()
    {
        var (slug, tunnel) = await NewTenantAndTunnelAsync();
        using var client = MtlsClient(_pki.IssueClient("edge-usage-1", [TestPki.ClientAuthOid]).Certificate);

        var (status, reply) = await ReportAsync(client, Request(slug, tunnel, count: 2));

        Assert.Equal("0", status);
        Assert.Equal(2u, reply!.Accepted);

        var rows = await RowsAsync(tunnel);
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.Equal("edge-usage-1", r.ReportedBy));
    }

    [Fact]
    public async Task Over_1000_windows_is_invalid_argument_on_the_wire()
    {
        var (slug, tunnel) = await NewTenantAndTunnelAsync();

        var (status, _) = await ReportAsync(_plaintext.Internal, Request(slug, tunnel, count: 1001));

        Assert.Equal("3", status); // InvalidArgument
        Assert.Empty(await RowsAsync(tunnel));
    }

    [Fact]
    public async Task Report_usage_is_not_served_on_public_listener()
    {
        var (slug, tunnel) = await NewTenantAndTunnelAsync();
        using var request = UsageTestSupport.GrpcRequest("ReportUsage", Request(slug, tunnel, count: 1));
        request.Version = HttpVersion.Version11;

        using var response = await _plaintext.Public.SendAsync(request);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Empty(await RowsAsync(tunnel));
    }
}
