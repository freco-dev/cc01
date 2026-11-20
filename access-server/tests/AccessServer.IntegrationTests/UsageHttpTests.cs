using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AccessServer.Domain.Entities;
using AccessServer.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>
/// GET /v1/usage — haqiqiy Kestrel'ning public listener'i orqali. Ma'lumot
/// to'g'ridan-to'g'ri bazaga yoziladi: ReportUsage 7 kundan eski oynani
/// qabul qilmaydi, bu yerda esa aniq sanalar kerak.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class UsageHttpTests(PostgresFixture fixture) : IAsyncLifetime
{
    private const string Password = "correct horse battery staple";

    private KestrelAccessApi _api = null!;

    public Task InitializeAsync()
    {
        _api = KestrelAccessApi.Start(fixture.ConnectionString, adminKey: null);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await _api.DisposeAsync();

    private sealed record Session(string Jwt, int TenantId);

    private async Task<Session> RegisterVerifyAndLoginAsync()
    {
        var email = $"uh{Guid.NewGuid():n}@example.com";

        var register = await _api.Public.PostAsJsonAsync("/v1/auth/register", new
        {
            fullName = "Aziz Karimov",
            email,
            password = Password,
            subscribe = false,
        });
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);
        var slug = register.Headers.Location!.OriginalString.Split('/')[^1];

        var verify = await _api.Public.PostAsJsonAsync("/v1/auth/verify-email",
            new { token = _api.Emails.TokenFor(email) });
        Assert.Equal(HttpStatusCode.NoContent, verify.StatusCode);

        var login = await _api.Public.PostAsJsonAsync("/v1/auth/login", new { email, password = Password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var jwt = JsonDocument.Parse(await login.Content.ReadAsStringAsync())
            .RootElement.GetProperty("accessToken").GetString()!;

        await using var scope = fixture.CreateScope();
        var tenantId = await scope.ServiceProvider.GetRequiredService<AccessDbContext>().Tenants
            .Where(t => t.Slug == slug).Select(t => t.Id).SingleAsync();

        return new Session(jwt, tenantId);
    }

    private static DateTimeOffset At(string iso) =>
        DateTimeOffset.Parse(iso, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);

    private async Task SeedAsync(int tenantId, params (DateTimeOffset Start, int Seconds, long BytesIn, long BytesOut, int Connections, int Rejected)[] windows)
    {
        await using var scope = fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tunnel = UsageTestSupport.UniqueTunnel();

        foreach (var w in windows)
        {
            db.UsageRecords.Add(new UsageRecord
            {
                TenantId = tenantId,
                TunnelId = tunnel,
                WindowStart = w.Start,
                WindowEnd = w.Start.AddSeconds(w.Seconds),
                BytesIn = w.BytesIn,
                BytesOut = w.BytesOut,
                Connections = w.Connections,
                Rejected = w.Rejected,
                ReportedBy = UsageRecord.PlaintextReporter,
            });
        }

        await db.SaveChangesAsync();
    }

    private async Task<(HttpStatusCode Status, JsonElement Body)> GetUsageAsync(string jwt, string query = "")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/usage" + query);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

        using var response = await _api.Public.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        return (response.StatusCode, JsonDocument.Parse(text).RootElement.Clone());
    }

    private static string Range(string from, string to) =>
        $"?from={Uri.EscapeDataString(from)}&to={Uri.EscapeDataString(to)}";

    [Fact]
    public async Task Get_usage_requires_jwt()
    {
        var response = await _api.Public.GetAsync("/v1/usage");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Daily_grouping_is_by_utc_day_of_window_start_and_totals_are_exact()
    {
        var session = await RegisterVerifyAndLoginAsync();
        await SeedAsync(session.TenantId,
            (At("2026-10-01T10:00:00Z"), 1200, 100, 1000, 2, 0),
            (At("2026-10-01T10:20:00Z"), 1200, 100, 1000, 3, 1),
            (At("2026-10-01T10:40:00Z"), 1200, 100, 1000, 0, 0),
            (At("2026-10-01T23:45:00Z"), 900, 7, 8, 1, 0),        // tugashi ertasiga o'tadi — baribir 1-oktabr
            (At("2026-10-02T00:00:00Z"), 60, 5, 6, 1, 2),
            (At("2026-10-04T12:00:00Z"), 3600, 0, 0, 0, 0));     // trafiksiz, lekin tunnel ochiq

        var (status, body) = await GetUsageAsync(session.Jwt,
            Range("2026-10-01T00:00:00Z", "2026-10-05T00:00:00Z"));

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(At("2026-10-01T00:00:00Z"), body.GetProperty("from").GetDateTimeOffset());
        Assert.Equal(At("2026-10-05T00:00:00Z"), body.GetProperty("to").GetDateTimeOffset());

        var daily = body.GetProperty("daily").EnumerateArray().ToArray();
        Assert.Equal(["2026-10-01", "2026-10-02", "2026-10-04"], daily.Select(d => d.GetProperty("date").GetString()));

        Assert.Equal(307, daily[0].GetProperty("bytesIn").GetInt64());
        Assert.Equal(3008, daily[0].GetProperty("bytesOut").GetInt64());
        Assert.Equal(6, daily[0].GetProperty("connections").GetInt64());
        Assert.Equal(1, daily[0].GetProperty("rejected").GetInt64());
        Assert.Equal(1.25m, daily[0].GetProperty("tunnelHours").GetDecimal());      // 3600 + 900 s

        Assert.Equal(5, daily[1].GetProperty("bytesIn").GetInt64());
        Assert.Equal(2, daily[1].GetProperty("rejected").GetInt64());
        Assert.Equal(0.02m, daily[1].GetProperty("tunnelHours").GetDecimal());      // 60 s = 0.0166…

        Assert.Equal(0, daily[2].GetProperty("bytesIn").GetInt64());
        Assert.Equal(1m, daily[2].GetProperty("tunnelHours").GetDecimal());

        var totals = body.GetProperty("totals");
        Assert.Equal(312, totals.GetProperty("bytesIn").GetInt64());
        Assert.Equal(3014, totals.GetProperty("bytesOut").GetInt64());
        Assert.Equal(7, totals.GetProperty("connections").GetInt64());
        Assert.Equal(3, totals.GetProperty("rejected").GetInt64());
        Assert.Equal(2.27m, totals.GetProperty("tunnelHours").GetDecimal());        // 8160 s = 2.2666…
    }

    [Fact]
    public async Task Total_tunnel_hours_are_rounded_once_not_summed_from_rounded_days()
    {
        var session = await RegisterVerifyAndLoginAsync();
        await SeedAsync(session.TenantId,
            (At("2026-09-01T12:00:00Z"), 100, 0, 0, 0, 0),
            (At("2026-09-02T12:00:00Z"), 100, 0, 0, 0, 0),
            (At("2026-09-03T12:00:00Z"), 100, 0, 0, 0, 0));

        var (_, body) = await GetUsageAsync(session.Jwt, Range("2026-09-01T00:00:00Z", "2026-09-04T00:00:00Z"));

        Assert.All(body.GetProperty("daily").EnumerateArray(),
            d => Assert.Equal(0.03m, d.GetProperty("tunnelHours").GetDecimal()));
        Assert.Equal(0.08m, body.GetProperty("totals").GetProperty("tunnelHours").GetDecimal()); // 300 s, 0.09 emas
    }

    [Fact]
    public async Task Range_is_half_open_on_window_start()
    {
        var session = await RegisterVerifyAndLoginAsync();
        await SeedAsync(session.TenantId,
            (At("2026-08-10T00:00:00Z"), 60, 1, 0, 0, 0),     // from — kiradi
            (At("2026-08-10T23:59:30Z"), 60, 10, 0, 0, 0),    // to dan oldin boshlangan — kiradi
            (At("2026-08-11T00:00:00Z"), 60, 100, 0, 0, 0));  // to — kirmaydi

        var (_, body) = await GetUsageAsync(session.Jwt, Range("2026-08-10T00:00:00Z", "2026-08-11T00:00:00Z"));

        Assert.Equal(11, body.GetProperty("totals").GetProperty("bytesIn").GetInt64());
    }

    [Fact]
    public async Task Offsets_in_query_are_normalized_to_utc()
    {
        var session = await RegisterVerifyAndLoginAsync();
        await SeedAsync(session.TenantId, (At("2026-07-31T20:00:00Z"), 60, 42, 0, 0, 0));

        // 2026-08-01T00:00+05:00 = 2026-07-31T19:00Z.
        var (status, body) = await GetUsageAsync(session.Jwt,
            Range("2026-08-01T00:00:00+05:00", "2026-08-02T00:00:00+05:00"));

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(TimeSpan.Zero, body.GetProperty("from").GetDateTimeOffset().Offset);
        Assert.Equal(At("2026-07-31T19:00:00Z"), body.GetProperty("from").GetDateTimeOffset());
        Assert.Equal(42, body.GetProperty("totals").GetProperty("bytesIn").GetInt64());
        Assert.Equal("2026-07-31", body.GetProperty("daily")[0].GetProperty("date").GetString());
    }

    [Fact]
    public async Task Default_range_is_last_30_days_until_now()
    {
        var session = await RegisterVerifyAndLoginAsync();
        var now = DateTimeOffset.UtcNow;
        await SeedAsync(session.TenantId,
            (now.AddDays(-1), 60, 1, 0, 0, 0),
            (now.AddDays(-29), 60, 10, 0, 0, 0),
            (now.AddDays(-31), 60, 100, 0, 0, 0));

        var before = DateTimeOffset.UtcNow;
        var (status, body) = await GetUsageAsync(session.Jwt);
        var after = DateTimeOffset.UtcNow;

        Assert.Equal(HttpStatusCode.OK, status);
        var to = body.GetProperty("to").GetDateTimeOffset();
        var from = body.GetProperty("from").GetDateTimeOffset();
        Assert.InRange(to, before, after);
        Assert.Equal(TimeSpan.FromDays(30), to - from);
        Assert.Equal(11, body.GetProperty("totals").GetProperty("bytesIn").GetInt64());

        // Faqat to berilsa — from = to − 30 kun.
        var (_, onlyTo) = await GetUsageAsync(session.Jwt, "?to=2026-06-30T00:00:00Z");
        Assert.Equal(At("2026-05-31T00:00:00Z"), onlyTo.GetProperty("from").GetDateTimeOffset());
    }

    [Fact]
    public async Task Empty_range_returns_zero_totals_and_no_days()
    {
        var session = await RegisterVerifyAndLoginAsync();

        var (status, body) = await GetUsageAsync(session.Jwt);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Empty(body.GetProperty("daily").EnumerateArray());
        var totals = body.GetProperty("totals");
        Assert.Equal(0, totals.GetProperty("bytesIn").GetInt64());
        Assert.Equal(0, totals.GetProperty("bytesOut").GetInt64());
        Assert.Equal(0, totals.GetProperty("connections").GetInt64());
        Assert.Equal(0, totals.GetProperty("rejected").GetInt64());
        Assert.Equal(0m, totals.GetProperty("tunnelHours").GetDecimal());
    }

    [Fact]
    public async Task Other_tenants_usage_is_invisible()
    {
        var alice = await RegisterVerifyAndLoginAsync();
        var bob = await RegisterVerifyAndLoginAsync();
        await SeedAsync(alice.TenantId, (At("2026-05-10T00:00:00Z"), 60, 1, 0, 0, 0));
        await SeedAsync(bob.TenantId, (At("2026-05-10T00:00:00Z"), 60, 1000, 0, 0, 0));

        // Tenant'ni so'rovdan tanlab bo'lmaydi (A-S15) — begona parametr e'tiborsiz.
        var (_, body) = await GetUsageAsync(alice.Jwt,
            Range("2026-05-01T00:00:00Z", "2026-06-01T00:00:00Z") + $"&tenantId={bob.TenantId}");

        Assert.Equal(1, body.GetProperty("totals").GetProperty("bytesIn").GetInt64());
        Assert.Single(body.GetProperty("daily").EnumerateArray());
    }

    [Fact]
    public async Task Byte_sums_beyond_bigint_are_clamped()
    {
        var session = await RegisterVerifyAndLoginAsync();
        await SeedAsync(session.TenantId,
            (At("2026-04-01T00:00:00Z"), 60, long.MaxValue, 1, 0, 0),
            (At("2026-04-01T00:01:00Z"), 60, long.MaxValue, 1, 0, 0));

        var (status, body) = await GetUsageAsync(session.Jwt, Range("2026-04-01T00:00:00Z", "2026-04-02T00:00:00Z"));

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(long.MaxValue, body.GetProperty("totals").GetProperty("bytesIn").GetInt64());
        Assert.Equal(2, body.GetProperty("totals").GetProperty("bytesOut").GetInt64());
    }

    [Theory]
    [InlineData("2026-10-02T00:00:00Z", "2026-10-01T00:00:00Z")]   // from > to
    [InlineData("2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z")]   // from = to
    [InlineData("2025-01-01T00:00:00Z", "2026-02-05T00:00:01Z")]   // 400 kun + 1 s
    [InlineData("kecha", "2026-10-01T00:00:00Z")]                  // ISO emas
    [InlineData("2026-10-01T00:00:00Z", "2026-13-01T00:00:00Z")]
    public async Task Invalid_range_is_400_usage_range_invalid(string from, string to)
    {
        var session = await RegisterVerifyAndLoginAsync();

        var (status, body) = await GetUsageAsync(session.Jwt, Range(from, to));

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("USAGE_RANGE_INVALID", body.GetProperty("code").GetString());
        Assert.Contains("oraliq", body.GetProperty("message").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Range_of_exactly_400_days_is_allowed()
    {
        var session = await RegisterVerifyAndLoginAsync();

        var (status, _) = await GetUsageAsync(session.Jwt, Range("2025-01-01T00:00:00Z", "2026-02-05T00:00:00Z"));

        Assert.Equal(HttpStatusCode.OK, status);
    }
}
