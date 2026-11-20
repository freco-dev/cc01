using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>
/// AddUsageRecords: up → down → up mavjud ma'lumot bilan, cheklovlar va
/// indekslar (`make db-verify` bo'sh bazada faqat yo'lni tekshiradi).
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class UsageMigrationTests(PostgresFixture fixture)
{
    private const string Previous = "20261119191255_AddPlansAndSubscriptions";

    private const string InsertRow = """
        INSERT INTO usage_records (tenant_id, tunnel_id, window_start, window_end, bytes_in, bytes_out,
                                   connections, rejected, reported_by, created_at, updated_at)
        SELECT id, 'tun_1', '2026-11-01T00:00:00Z', '2026-11-01T00:01:00Z', 1, 2, 3, 4, 'plaintext', now(), now()
        FROM tenants WHERE slug = 't_usage'
        """;

    [Fact]
    public async Task Up_down_up_with_data_and_constraints()
    {
        var connectionString = await fixture.CreateScratchDatabaseAsync();
        try
        {
            await using var db = PostgresFixture.CreateContext(connectionString);
            var migrator = db.GetService<IMigrator>();

            await migrator.MigrateAsync(Previous);
            await ExecuteAsync(connectionString, """
                INSERT INTO tenants (slug, name, status, created_at, updated_at)
                VALUES ('t_usage', 'U', 'Active', now(), now());
                """);

            // ── up ────────────────────────────────────────────────────────
            await migrator.MigrateAsync();

            Assert.Equal(
                ["ix_usage_records_tenant_id_window_start", "ix_usage_records_tunnel_id_window_start", "pk_usage_records"],
                await IndexesAsync(connectionString));

            await ExecuteAsync(connectionString, InsertRow);

            // (tunnel_id, window_start) unique — ON CONFLICT shunga tayanadi.
            var duplicate = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connectionString, InsertRow));
            Assert.Equal(PostgresErrorCodes.UniqueViolation, duplicate.SqlState);

            var inverted = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connectionString, """
                INSERT INTO usage_records (tenant_id, tunnel_id, window_start, window_end, bytes_in, bytes_out,
                                           connections, rejected, reported_by, created_at, updated_at)
                SELECT id, 'tun_2', '2026-11-01T00:01:00Z', '2026-11-01T00:01:00Z', 0, 0, 0, 0, 'plaintext', now(), now()
                FROM tenants WHERE slug = 't_usage'
                """));
            Assert.Equal(PostgresErrorCodes.CheckViolation, inverted.SqlState);

            // Model ham jadvalni o'qiy oladi.
            var row = await db.UsageRecords.AsNoTracking().SingleAsync();
            Assert.Equal(1, row.BytesIn);
            Assert.Equal("plaintext", row.ReportedBy);

            // ── down ──────────────────────────────────────────────────────
            await migrator.MigrateAsync(Previous);

            Assert.False(await ScalarAsync<bool>(connectionString, "SELECT to_regclass('public.usage_records') IS NOT NULL"));
            Assert.Equal(1L, await ScalarAsync<long>(connectionString, "SELECT count(*) FROM tenants"));

            // ── yana up ───────────────────────────────────────────────────
            await migrator.MigrateAsync();
            await ExecuteAsync(connectionString, InsertRow);

            // Tenant o'chirilsa — usage ham (cascade).
            await ExecuteAsync(connectionString, "DELETE FROM tenants WHERE slug = 't_usage'");
            Assert.Equal(0L, await ScalarAsync<long>(connectionString, "SELECT count(*) FROM usage_records"));
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

    private static async Task<List<string>> IndexesAsync(string connectionString)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(
            "SELECT indexname FROM pg_indexes WHERE tablename = 'usage_records' ORDER BY indexname", connection);
        await using var reader = await command.ExecuteReaderAsync();

        var names = new List<string>();
        while (await reader.ReadAsync())
        {
            names.Add(reader.GetString(0));
        }

        return names;
    }
}
