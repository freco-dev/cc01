using AccessServer.Application.Plans;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>
/// `make db-verify` bo'sh bazada up → down → up'ni tekshiradi. Bu yerda esa
/// xuddi shu yo'l MA'LUMOT bilan: backfill har bir tenantning tarifini
/// saqlaydimi va Down uni tenants.plan'ga qaytaradimi.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class PlanMigrationTests(PostgresFixture fixture)
{
    private const string Initial = "20260820093755_InitialAccessSchema";

    [Fact]
    public async Task Backfill_maps_existing_tenants_and_down_restores_plan()
    {
        var connectionString = await fixture.CreateScratchDatabaseAsync();
        try
        {
            await using var db = PostgresFixture.CreateContext(connectionString);
            var migrator = db.GetService<IMigrator>();

            await migrator.MigrateAsync(Initial);

            // 'Gold' — qo'lda yozilgan noma'lum qiymat; Free'ga tushishi kerak.
            await ExecuteAsync(connectionString, """
                INSERT INTO tenants (slug, name, plan, status, created_at, updated_at) VALUES
                    ('t_pro',  'P', 'Pro',  'Active', now() - interval '3 days', now()),
                    ('t_free', 'F', 'Free', 'Active', now(), now()),
                    ('t_gold', 'G', 'Gold', 'Active', now(), now());
                """);

            // ── up ────────────────────────────────────────────────────────
            await migrator.MigrateAsync();

            Assert.Equal(
                new Dictionary<string, string>
                {
                    ["t_free"] = "Free",
                    ["t_gold"] = "Free",
                    ["t_pro"] = "Pro",
                },
                await SubscriptionPlansAsync(connectionString));

            Assert.False(await TenantPlanColumnExistsAsync(connectionString));
            Assert.Equal(3L, await ScalarAsync<long>(connectionString, "SELECT count(*) FROM plans"));
            Assert.Equal(0L, await ScalarAsync<long>(connectionString,
                "SELECT count(*) FROM subscriptions WHERE status <> 'Active' OR period_end IS NOT NULL"));

            // Backfill davr boshini tenant yaratilgan vaqtdan oladi.
            Assert.True(await ScalarAsync<bool>(connectionString, """
                SELECT s.period_start = t.created_at
                FROM subscriptions s JOIN tenants t ON t.id = s.tenant_id
                WHERE t.slug = 't_pro'
                """));

            // Backfill qilingan qatorlar model orqali ham to'g'ri o'qiladi.
            var proTenantId = await db.Tenants.Where(t => t.Slug == "t_pro").Select(t => t.Id).SingleAsync();
            var resolved = await new EffectivePlanResolver(db, TimeProvider.System).ResolveAsync(proTenantId);
            Assert.Equal(PlanCode.Pro, resolved.Code);
            Assert.Equal(128, resolved.Limits.MaxConnectionsPerTunnel);
            Assert.Equal(EffectivePlanSource.Subscription, resolved.Source);

            // ── down ──────────────────────────────────────────────────────
            await migrator.MigrateAsync(Initial);

            Assert.Equal(
                new Dictionary<string, string>
                {
                    ["t_free"] = "Free",
                    ["t_gold"] = "Free",
                    ["t_pro"] = "Pro",
                },
                await TenantPlansAsync(connectionString));

            Assert.False(await TableExistsAsync(connectionString, "plans"));
            Assert.False(await TableExistsAsync(connectionString, "subscriptions"));
            Assert.False(await TableExistsAsync(connectionString, "audit_events"));

            // Sxema Initial bilan bir xil: default qolmagan.
            Assert.Null(await ScalarAsync<string?>(connectionString, """
                SELECT column_default FROM information_schema.columns
                WHERE table_name = 'tenants' AND column_name = 'plan'
                """));

            // ── yana up ───────────────────────────────────────────────────
            await migrator.MigrateAsync();

            Assert.Equal(
                new Dictionary<string, string>
                {
                    ["t_free"] = "Free",
                    ["t_gold"] = "Free",
                    ["t_pro"] = "Pro",
                },
                await SubscriptionPlansAsync(connectionString));
        }
        finally
        {
            await PostgresFixture.DropScratchDatabaseAsync(connectionString);
        }
    }

    [Fact]
    public async Task Down_restores_only_the_currently_effective_plan()
    {
        // Down xom p.code'ni ko'chirsa, tugagan sinov muddati yoki bekor
        // qilingan obuna Faza 0 sxemasida MUDDATSIZ Pro bo'lib qolardi.
        // Qoida EffectivePlanResolver bilan bir xil bo'lishi kerak.
        var connectionString = await fixture.CreateScratchDatabaseAsync();
        try
        {
            await using var db = PostgresFixture.CreateContext(connectionString);
            var migrator = db.GetService<IMigrator>();

            await migrator.MigrateAsync(Initial);

            await ExecuteAsync(connectionString, """
                INSERT INTO tenants (slug, name, plan, status, created_at, updated_at) VALUES
                    ('t_expired',  'E', 'Pro',        'Active', now() - interval '30 days', now()),
                    ('t_canceled', 'C', 'Pro',        'Active', now() - interval '30 days', now()),
                    ('t_trial',    'T', 'Pro',        'Active', now() - interval '30 days', now()),
                    ('t_forever',  'F', 'Enterprise', 'Active', now() - interval '30 days', now());
                """);

            await migrator.MigrateAsync();

            // Faza 1 holati: muddati o'tgan, bekor qilingan, hali amaldagi
            // sinov muddati va muddatsiz obuna.
            await ExecuteAsync(connectionString, """
                UPDATE subscriptions s SET period_end = now() - interval '1 day'
                FROM tenants t WHERE t.id = s.tenant_id AND t.slug = 't_expired';

                UPDATE subscriptions s SET status = 'Canceled'
                FROM tenants t WHERE t.id = s.tenant_id AND t.slug = 't_canceled';

                UPDATE subscriptions s SET period_end = now() + interval '7 days'
                FROM tenants t WHERE t.id = s.tenant_id AND t.slug = 't_trial';
                """);

            // Model ham xuddi shunday deydi — Down shu bilan mos bo'lishi kerak.
            var resolver = new EffectivePlanResolver(db, TimeProvider.System);
            var expiredId = await db.Tenants.Where(t => t.Slug == "t_expired").Select(t => t.Id).SingleAsync();
            Assert.Equal(EffectivePlanSource.Expired, (await resolver.ResolveAsync(expiredId)).Source);

            await migrator.MigrateAsync(Initial);

            Assert.Equal(
                new Dictionary<string, string>
                {
                    ["t_canceled"] = "Free",
                    ["t_expired"] = "Free",
                    ["t_forever"] = "Enterprise",
                    ["t_trial"] = "Pro",
                },
                await TenantPlansAsync(connectionString));
        }
        finally
        {
            await PostgresFixture.DropScratchDatabaseAsync(connectionString);
        }
    }

    [Fact]
    public async Task New_plan_row_gets_id_from_identity_without_collision()
    {
        var connectionString = await fixture.CreateScratchDatabaseAsync();
        try
        {
            await using (var db = PostgresFixture.CreateContext(connectionString))
            {
                await db.Database.MigrateAsync();
            }

            // Seed 1–3 id'larni oshkora oladi; yangi qator identity'dan keladi
            // va ular bilan to'qnashmasligi kerak.
            var id = await ScalarAsync<int>(connectionString, """
                INSERT INTO plans (code, name, max_subdomains, max_tunnels, max_conns_per_tunnel, bandwidth_bps, created_at, updated_at)
                VALUES ('Team', 'Team', 5, 5, 64, 0, now(), now())
                RETURNING id
                """);

            Assert.True(id >= 100, $"id={id}");
        }
        finally
        {
            await PostgresFixture.DropScratchDatabaseAsync(connectionString);
        }
    }

    private static async Task ExecuteAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<T> ScalarAsync<T>(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        var value = await command.ExecuteScalarAsync();
        return value is null or DBNull ? default! : (T)value;
    }

    private static Task<Dictionary<string, string>> SubscriptionPlansAsync(string connectionString) =>
        PairsAsync(connectionString, """
            SELECT t.slug, p.code
            FROM subscriptions s
            JOIN tenants t ON t.id = s.tenant_id
            JOIN plans p ON p.id = s.plan_id
            """);

    private static Task<Dictionary<string, string>> TenantPlansAsync(string connectionString) =>
        PairsAsync(connectionString, "SELECT slug, plan FROM tenants");

    private static async Task<Dictionary<string, string>> PairsAsync(string connectionString, string sql)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync();

        var result = new Dictionary<string, string>();
        while (await reader.ReadAsync())
        {
            result[reader.GetString(0)] = reader.GetString(1);
        }

        return result;
    }

    private static Task<bool> TenantPlanColumnExistsAsync(string connectionString) =>
        ScalarAsync<bool>(connectionString, """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'tenants' AND column_name = 'plan')
            """);

    private static Task<bool> TableExistsAsync(string connectionString, string table) =>
        ScalarAsync<bool>(connectionString,
            $"SELECT to_regclass('public.{table}') IS NOT NULL");
}
