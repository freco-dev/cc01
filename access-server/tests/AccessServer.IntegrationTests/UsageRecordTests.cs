using AccessServer.Api.Grpc;
using AccessServer.Application.Abstractions;
using AccessServer.Application.Tunnels;
using AccessServer.Application.Usage;
using AccessServer.Domain.Entities;
using AccessServer.Infrastructure.Persistence;
using Cc01.V1;
using Grpc.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>
/// ReportUsage semantikasi — RecordUsageHandler + haqiqiy Postgres'dagi
/// UsageStore. Simdan o'tishi <see cref="UsageGrpcTests"/> da.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class UsageRecordTests(PostgresFixture fixture)
{
    /// <summary>Soniyaga yaxlitlangan "hozir" — chegaralar aniq bo'lsin.</summary>
    private static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    private static readonly long NowUnix = Now.ToUnixTimeSeconds();

    private static UsageWindowInput Window(
        string slug,
        string tunnel,
        long start,
        long? end = null,
        ulong bytesIn = 100,
        ulong bytesOut = 200,
        uint connections = 3,
        uint rejected = 1) =>
        new(slug, tunnel, start, end ?? start + 60, bytesIn, bytesOut, connections, rejected);

    private RecordUsageHandler Handler(
        AsyncServiceScope scope,
        ILogger<RecordUsageHandler>? logger = null) =>
        new(scope.ServiceProvider.GetRequiredService<IUsageStore>(),
            new FixedTimeProvider(Now),
            logger ?? NullLogger<RecordUsageHandler>.Instance);

    private async Task<Tenant> CreateTenantAsync()
    {
        await using var scope = fixture.CreateScope();
        return await UsageTestSupport.CreateTenantAsync(scope.ServiceProvider.GetRequiredService<AccessDbContext>());
    }

    private async Task<List<UsageRecord>> RowsAsync(params string[] tunnels)
    {
        await using var scope = fixture.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AccessDbContext>().UsageRecords
            .AsNoTracking()
            .Where(u => tunnels.Contains(u.TunnelId))
            .OrderBy(u => u.TunnelId).ThenBy(u => u.WindowStart)
            .ToListAsync();
    }

    private async Task<RecordUsageOutcome> RecordAsync(
        IReadOnlyList<UsageWindowInput> windows,
        string reportedBy = UsageRecord.PlaintextReporter,
        ILogger<RecordUsageHandler>? logger = null)
    {
        await using var scope = fixture.CreateScope();
        var result = await Handler(scope, logger).HandleAsync(new RecordUsageCommand(windows, reportedBy));
        Assert.True(result.IsSuccess, result.Error?.Code);
        return result.Value;
    }

    [Fact]
    public async Task Valid_window_is_stored_with_all_fields()
    {
        var tenant = await CreateTenantAsync();
        var tunnel = UsageTestSupport.UniqueTunnel();
        var start = NowUnix - 120;

        var outcome = await RecordAsync(
            [Window(tenant.Slug, tunnel, start, start + 60, bytesIn: 1234, bytesOut: 5678, connections: 7, rejected: 2)],
            reportedBy: "edge-1");

        Assert.Equal(new RecordUsageOutcome(1, 1, 0, 0), outcome);

        var row = Assert.Single(await RowsAsync(tunnel));
        Assert.Equal(tenant.Id, row.TenantId);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(start), row.WindowStart);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(start + 60), row.WindowEnd);
        Assert.Equal(1234, row.BytesIn);
        Assert.Equal(5678, row.BytesOut);
        Assert.Equal(7, row.Connections);
        Assert.Equal(2, row.Rejected);
        Assert.Equal("edge-1", row.ReportedBy);
        Assert.Equal(Now, row.CreatedAt);
        Assert.Equal(Now, row.UpdatedAt);
    }

    [Fact]
    public async Task Same_batch_twice_stores_each_window_once_and_accepts_both_times()
    {
        var tenant = await CreateTenantAsync();
        var tunnel = UsageTestSupport.UniqueTunnel();
        var batch = new[]
        {
            Window(tenant.Slug, tunnel, NowUnix - 180),
            Window(tenant.Slug, tunnel, NowUnix - 120),
            Window(tenant.Slug, tunnel, NowUnix - 60),
        };

        var first = await RecordAsync(batch);
        var second = await RecordAsync(batch);

        Assert.Equal(new RecordUsageOutcome(3, 3, 0, 0), first);
        Assert.Equal(new RecordUsageOutcome(3, 0, 3, 0), second);
        Assert.Equal(3, (await RowsAsync(tunnel)).Count);
    }

    [Fact]
    public async Task Retry_with_different_values_keeps_first_write()
    {
        var tenant = await CreateTenantAsync();
        var tunnel = UsageTestSupport.UniqueTunnel();

        await RecordAsync([Window(tenant.Slug, tunnel, NowUnix - 60, bytesIn: 1)], reportedBy: "edge-1");
        var retry = await RecordAsync([Window(tenant.Slug, tunnel, NowUnix - 60, bytesIn: 999)], reportedBy: "edge-2");

        Assert.Equal(new RecordUsageOutcome(1, 0, 1, 0), retry);
        var row = Assert.Single(await RowsAsync(tunnel));
        Assert.Equal(1, row.BytesIn);
        Assert.Equal("edge-1", row.ReportedBy);
    }

    [Fact]
    public async Task Duplicate_inside_one_batch_is_counted_as_duplicate()
    {
        var tenant = await CreateTenantAsync();
        var tunnel = UsageTestSupport.UniqueTunnel();

        var outcome = await RecordAsync(
        [
            Window(tenant.Slug, tunnel, NowUnix - 60),
            Window(tenant.Slug, tunnel, NowUnix - 60),
        ]);

        Assert.Equal(new RecordUsageOutcome(2, 1, 1, 0), outcome);
        Assert.Single(await RowsAsync(tunnel));
    }

    [Fact]
    public async Task Concurrent_duplicate_batches_store_each_window_once()
    {
        var tenant = await CreateTenantAsync();
        var tunnels = Enumerable.Range(0, 5).Select(_ => UsageTestSupport.UniqueTunnel()).ToArray();
        var windows = tunnels
            .SelectMany(tunnel => Enumerable.Range(1, 40).Select(i => Window(tenant.Slug, tunnel, NowUnix - (i * 60))))
            .ToArray();

        // Har bir parallel hisobot oynalarni boshqa tartibda yuboradi —
        // tartiblanmagan qo'shish shu yerda deadlock'ka tushardi.
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 8).Select(i =>
        {
            var shuffled = windows.OrderBy(_ => Random.Shared.Next()).ToArray();
            return Task.Run(() => RecordAsync(shuffled));
        }));

        Assert.All(outcomes, o => Assert.Equal(windows.Length, o.Received));
        Assert.All(outcomes, o => Assert.Equal(0, o.Dropped));
        Assert.Equal(windows.Length, outcomes.Sum(o => o.Inserted));
        Assert.Equal(windows.Length * 7, outcomes.Sum(o => o.Duplicate));
        Assert.Equal(windows.Length, (await RowsAsync(tunnels)).Count);
    }

    [Fact]
    public async Task Invalid_windows_are_dropped_and_valid_ones_in_same_batch_are_stored()
    {
        var tenant = await CreateTenantAsync();
        var valid = UsageTestSupport.UniqueTunnel();
        var invalid = UsageTestSupport.UniqueTunnel();
        var logger = new CapturingLogger<RecordUsageHandler>();
        var start = NowUnix - 600;

        var outcome = await RecordAsync(
        [
            Window(tenant.Slug, valid, start),

            // tunnel_id
            Window(tenant.Slug, "", start),
            Window(tenant.Slug, new string('x', 129), start),
            Window(tenant.Slug, invalid + "\n", start),
            Window(tenant.Slug, invalid + "\0", start),

            // vaqt
            Window(tenant.Slug, invalid, start, start),                          // uzunligi 0
            Window(tenant.Slug, invalid, start, start - 60),                     // teskari
            Window(tenant.Slug, invalid, start - 3000, start + 601),             // > 3600 s
            Window(tenant.Slug, invalid, NowUnix - (7 * 86400) - 1),             // 7 kundan eski
            Window(tenant.Slug, invalid, NowUnix, NowUnix + 301),                // kelajakda > 5 daq
            Window(tenant.Slug, invalid, long.MinValue, long.MaxValue),          // to'lib ketish

            // tenant
            Window("", invalid, start),
            Window("t_\0bad", invalid, start),
            Window("t_does_not_exist", invalid, start),
        ], logger: logger);

        Assert.Equal(new RecordUsageOutcome(14, 1, 0, 13), outcome);
        Assert.Single(await RowsAsync(valid));
        Assert.Empty(await RowsAsync(invalid, invalid + "\n", new string('x', 129)));

        var warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Equal(13, warning.State["Dropped"]);
        Assert.Equal(
            "TenantUnknown=3, TunnelIdInvalid=4, WindowInverted=2, WindowTooLong=1, WindowTooOld=2, WindowInFuture=1",
            warning.State["Reasons"]);

        // A-S9: klient qiymatlari (slug, tunnel_id) log'ga tushmaydi.
        Assert.All(logger.Entries, e =>
        {
            Assert.DoesNotContain(tenant.Slug, e.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(invalid, e.Message, StringComparison.Ordinal);
            Assert.DoesNotContain("t_does_not_exist", e.Message, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Window_limits_are_inclusive()
    {
        var tenant = await CreateTenantAsync();
        var tunnel = UsageTestSupport.UniqueTunnel();
        var oldest = NowUnix - (7 * 86400);

        var outcome = await RecordAsync(
        [
            Window(tenant.Slug, tunnel, oldest),                              // aynan 7 kun
            Window(tenant.Slug, tunnel, NowUnix - 3600, NowUnix),             // aynan 3600 s
            Window(tenant.Slug, tunnel, NowUnix + 240, NowUnix + 300),        // aynan +5 daq
        ]);

        Assert.Equal(new RecordUsageOutcome(3, 3, 0, 0), outcome);
    }

    [Fact]
    public async Task Unknown_tenant_is_dropped_and_others_are_stored()
    {
        var tenant = await CreateTenantAsync();
        var tunnel = UsageTestSupport.UniqueTunnel();
        var orphan = UsageTestSupport.UniqueTunnel();
        var logger = new CapturingLogger<RecordUsageHandler>();

        var outcome = await RecordAsync(
        [
            Window(tenant.Slug, tunnel, NowUnix - 60),
            Window("t_000000000000", orphan, NowUnix - 60),
            Window("t_000000000000", orphan, NowUnix - 120),
        ], logger: logger);

        Assert.Equal(new RecordUsageOutcome(3, 1, 0, 2), outcome);
        Assert.Single(await RowsAsync(tunnel));
        Assert.Empty(await RowsAsync(orphan));

        var warning = Assert.Single(logger.Entries, e => e.Level == LogLevel.Warning);
        Assert.Equal("TenantUnknown=2", warning.State["Reasons"]);
    }

    [Fact]
    public async Task Huge_counters_are_clamped()
    {
        var tenant = await CreateTenantAsync();
        var tunnel = UsageTestSupport.UniqueTunnel();

        await RecordAsync(
        [
            Window(tenant.Slug, tunnel, NowUnix - 60,
                bytesIn: ulong.MaxValue,
                bytesOut: (ulong)long.MaxValue + 1,
                connections: uint.MaxValue,
                rejected: (uint)int.MaxValue + 1),
        ]);

        var row = Assert.Single(await RowsAsync(tunnel));
        Assert.Equal(long.MaxValue, row.BytesIn);
        Assert.Equal(long.MaxValue, row.BytesOut);
        Assert.Equal(int.MaxValue, row.Connections);
        Assert.Equal(int.MaxValue, row.Rejected);
    }

    [Fact]
    public async Task Batch_is_logged_at_information_with_counts_and_reporter()
    {
        var tenant = await CreateTenantAsync();
        var tunnel = UsageTestSupport.UniqueTunnel();
        await RecordAsync([Window(tenant.Slug, tunnel, NowUnix - 60)]);

        var logger = new CapturingLogger<RecordUsageHandler>();
        await RecordAsync(
            [Window(tenant.Slug, tunnel, NowUnix - 60), Window(tenant.Slug, tunnel, NowUnix - 120), Window("", tunnel, 0)],
            reportedBy: "edge-7",
            logger: logger);

        var info = Assert.Single(logger.Entries, e => e.Level == LogLevel.Information);
        Assert.Equal(3, info.State["Received"]);
        Assert.Equal(1, info.State["Inserted"]);
        Assert.Equal(1, info.State["Duplicate"]);
        Assert.Equal(1, info.State["Dropped"]);
        Assert.Equal("edge-7", info.State["ReportedBy"]);
    }

    [Fact]
    public async Task Batch_of_1000_is_accepted_and_1001_is_rejected()
    {
        var tenant = await CreateTenantAsync();
        var tunnel = UsageTestSupport.UniqueTunnel();
        var windows = Enumerable.Range(0, 1001).Select(i => Window(tenant.Slug, tunnel, NowUnix - 60 - (i * 60))).ToArray();

        await using var scope = fixture.CreateScope();
        var tooLarge = await Handler(scope).HandleAsync(new RecordUsageCommand(windows, "plaintext"));
        Assert.Equal(UsageErrors.BatchTooLarge, tooLarge.Error);
        Assert.Empty(await RowsAsync(tunnel));

        var outcome = await RecordAsync(windows[..1000]);
        Assert.Equal(new RecordUsageOutcome(1000, 1000, 0, 0), outcome);
    }

    [Fact]
    public async Task Empty_batch_touches_nothing()
    {
        var outcome = await RecordAsync([]);
        Assert.Equal(new RecordUsageOutcome(0, 0, 0, 0), outcome);
    }

    // ───────────────────── gRPC servisi: status xaritasi ─────────────────────

    private async Task<ReportUsageResponse> InvokeAsync(IUsageStore store, ReportUsageRequest request)
    {
        await using var scope = fixture.CreateScope();
        var service = new TunnelAuthorizationService(
            scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>(),
            new RecordUsageHandler(store, new FixedTimeProvider(Now), NullLogger<RecordUsageHandler>.Instance),
            NullLogger<TunnelAuthorizationService>.Instance);

        return await service.ReportUsage(request, new UsageServerCallContext());
    }

    private static ReportUsageRequest Request(string slug, string tunnel, int count = 1)
    {
        var request = new ReportUsageRequest();
        for (var i = 0; i < count; i++)
        {
            request.Windows.Add(new UsageWindow
            {
                TenantId = slug,
                TunnelId = tunnel,
                WindowStart = NowUnix - 60 - (i * 60),
                WindowEnd = NowUnix - (i * 60),
                BytesIn = 1,
            });
        }

        return request;
    }

    [Fact]
    public async Task Database_down_maps_to_unavailable()
    {
        // 1-port — hech kim tinglamaydi; retry'siz kontekst, test tez.
        var builder = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Port = 1, Timeout = 2 };
        await using var db = PostgresFixture.CreateContext(builder.ConnectionString);

        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            InvokeAsync(new UsageStore(db), Request("t_any", UsageTestSupport.UniqueTunnel())));

        Assert.Equal(StatusCode.Unavailable, ex.StatusCode);
    }

    [Fact]
    public async Task Exhausted_retries_map_to_unavailable()
    {
        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            InvokeAsync(new ThrowingStore(new RetryLimitExceededException("x", new TimeoutException())),
                Request("t_any", UsageTestSupport.UniqueTunnel())));

        Assert.Equal(StatusCode.Unavailable, ex.StatusCode);
    }

    [Fact]
    public async Task Non_database_bug_is_not_reported_as_unavailable()
    {
        // Dasturdagi xato edge'ni cheksiz qayta urinishga majburlamasin.
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            InvokeAsync(new ThrowingStore(new InvalidOperationException("bug")),
                Request("t_any", UsageTestSupport.UniqueTunnel())));
    }

    [Fact]
    public async Task Service_rejects_more_than_1000_windows_with_invalid_argument()
    {
        await using var scope = fixture.CreateScope();
        var ex = await Assert.ThrowsAsync<RpcException>(() =>
            InvokeAsync(scope.ServiceProvider.GetRequiredService<IUsageStore>(),
                Request("t_any", UsageTestSupport.UniqueTunnel(), count: 1001)));

        Assert.Equal(StatusCode.InvalidArgument, ex.StatusCode);
    }

    [Fact]
    public async Task Service_accepts_whole_batch_including_dropped_and_duplicates()
    {
        var tenant = await CreateTenantAsync();
        var tunnel = UsageTestSupport.UniqueTunnel();
        await using var scope = fixture.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IUsageStore>();

        var request = Request(tenant.Slug, tunnel, count: 3);
        request.Windows.Add(new UsageWindow { TenantId = "t_unknown_xx", TunnelId = tunnel, WindowStart = 1, WindowEnd = 2 });

        Assert.Equal(4u, (await InvokeAsync(store, request)).Accepted);
        Assert.Equal(4u, (await InvokeAsync(store, request)).Accepted);

        var rows = await RowsAsync(tunnel);
        Assert.Equal(3, rows.Count);
        Assert.All(rows, r => Assert.Equal(UsageRecord.PlaintextReporter, r.ReportedBy));
    }

    private sealed class ThrowingStore(Exception exception) : IUsageStore
    {
        public Task<UsageInsertOutcome> InsertAsync(
            IReadOnlyList<UsageRecordDraft> drafts,
            string reportedBy,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) => Task.FromException<UsageInsertOutcome>(exception);

        public Task<UsageAggregate> AggregateAsync(
            int tenantId,
            DateTimeOffset from,
            DateTimeOffset to,
            CancellationToken cancellationToken = default) => Task.FromException<UsageAggregate>(exception);
    }
}
