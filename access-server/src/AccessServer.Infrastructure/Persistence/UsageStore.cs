using AccessServer.Application.Abstractions;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using NpgsqlTypes;

namespace AccessServer.Infrastructure.Persistence;

/// <summary>
/// usage_records uchun xom SQL (qarang <see cref="IUsageStore"/>). AccessDbContext
/// ulanishi va retry strategiyasidan foydalanadi; har bir amal — bitta so'rov.
/// </summary>
public sealed class UsageStore(AccessDbContext db) : IUsageStore
{
    /// <summary>
    /// Butun hisobot — bitta so'rov (massiv parametrlar + unnest), parametrlar
    /// soni oynalar soniga bog'liq emas.
    ///
    /// * Tenant slug → id shu so'rovning o'zida (JOIN): noma'lum slug'li oyna
    ///   qo'shilmaydi va <c>known</c> ga kirmaydi.
    /// * ON CONFLICT (tunnel_id, window_start) DO NOTHING: takror (edge qayta
    ///   yuborgani yoki parallel hisobot) jimgina tashlanadi, birinchi yozuv
    ///   yutadi. Bitta hisobot ichidagi takror ham shunday.
    /// * ORDER BY: parallel hisobotlar kalitlarni bir xil tartibda qulflaydi —
    ///   aks holda bir-birining unique-indeks qulfini kutib deadlock bo'lardi.
    /// </summary>
    private const string InsertSql = """
        WITH input AS (
            SELECT *
            FROM unnest(@slugs, @tunnel_ids, @starts, @ends, @bytes_in, @bytes_out, @connections, @rejected)
                AS w(slug, tunnel_id, window_start, window_end, bytes_in, bytes_out, connections, rejected)
        ),
        resolved AS (
            SELECT t.id AS tenant_id, w.tunnel_id, w.window_start, w.window_end,
                   w.bytes_in, w.bytes_out, w.connections, w.rejected
            FROM input w
            JOIN tenants t ON t.slug = w.slug
        ),
        inserted AS (
            INSERT INTO usage_records (tenant_id, tunnel_id, window_start, window_end, bytes_in, bytes_out,
                                       connections, rejected, reported_by, created_at, updated_at)
            SELECT tenant_id, tunnel_id, window_start, window_end, bytes_in, bytes_out,
                   connections, rejected, @reported_by, @now, @now
            FROM resolved
            ORDER BY tunnel_id, window_start
            ON CONFLICT (tunnel_id, window_start) DO NOTHING
            RETURNING 1
        )
        SELECT (SELECT count(*) FROM resolved)::integer AS known,
               (SELECT count(*) FROM inserted)::integer AS inserted
        """;

    /// <summary>
    /// GROUPING SETS: har bir UTC kun va jami bitta so'rovda; jami qatorida
    /// day = NULL. Bayt yig'indisi numeric — bigint'ga qisib olinadi.
    /// (tenant_id, window_start) indeksi diapazonni beradi.
    /// </summary>
    private const string AggregateSql = """
        SELECT day,
               LEAST(COALESCE(sum(bytes_in), 0), 9223372036854775807)::bigint  AS bytes_in,
               LEAST(COALESCE(sum(bytes_out), 0), 9223372036854775807)::bigint AS bytes_out,
               COALESCE(sum(connections), 0)::bigint                           AS connections,
               COALESCE(sum(rejected), 0)::bigint                              AS rejected,
               COALESCE(sum(seconds), 0)::bigint                               AS tunnel_seconds
        FROM (
            SELECT (window_start AT TIME ZONE 'UTC')::date AS day,
                   bytes_in, bytes_out, connections, rejected,
                   extract(epoch FROM window_end - window_start) AS seconds
            FROM usage_records
            WHERE tenant_id = @tenant_id
              AND window_start >= @from
              AND window_start < @to
        ) u
        GROUP BY GROUPING SETS ((day), ())
        ORDER BY day NULLS LAST
        """;

    public Task<UsageInsertOutcome> InsertAsync(
        IReadOnlyList<UsageRecordDraft> drafts,
        string reportedBy,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(drafts);
        ArgumentException.ThrowIfNullOrEmpty(reportedBy);

        return ExecuteAsync(async (connection, ct) =>
        {
            await using var command = new NpgsqlCommand(InsertSql, connection);
            var parameters = command.Parameters;

            parameters.Add(Array("slugs", NpgsqlDbType.Text, drafts.Select(d => d.TenantSlug)));
            parameters.Add(Array("tunnel_ids", NpgsqlDbType.Text, drafts.Select(d => d.TunnelId)));
            parameters.Add(Array("starts", NpgsqlDbType.TimestampTz, drafts.Select(d => d.WindowStart.ToUniversalTime())));
            parameters.Add(Array("ends", NpgsqlDbType.TimestampTz, drafts.Select(d => d.WindowEnd.ToUniversalTime())));
            parameters.Add(Array("bytes_in", NpgsqlDbType.Bigint, drafts.Select(d => d.BytesIn)));
            parameters.Add(Array("bytes_out", NpgsqlDbType.Bigint, drafts.Select(d => d.BytesOut)));
            parameters.Add(Array("connections", NpgsqlDbType.Integer, drafts.Select(d => d.Connections)));
            parameters.Add(Array("rejected", NpgsqlDbType.Integer, drafts.Select(d => d.Rejected)));
            parameters.Add(new NpgsqlParameter<string>("reported_by", NpgsqlDbType.Varchar) { TypedValue = reportedBy });
            parameters.Add(new NpgsqlParameter<DateTimeOffset>("now", NpgsqlDbType.TimestampTz)
            {
                TypedValue = now.ToUniversalTime(),
            });

            await using var reader = await command.ExecuteReaderAsync(ct);
            await reader.ReadAsync(ct);
            return new UsageInsertOutcome(reader.GetInt32(0), reader.GetInt32(1));
        }, cancellationToken);
    }

    public Task<UsageAggregate> AggregateAsync(
        int tenantId,
        DateTimeOffset from,
        DateTimeOffset to,
        CancellationToken cancellationToken = default)
    {
        return ExecuteAsync(async (connection, ct) =>
        {
            await using var command = new NpgsqlCommand(AggregateSql, connection);
            command.Parameters.Add(new NpgsqlParameter<int>("tenant_id", NpgsqlDbType.Integer) { TypedValue = tenantId });
            command.Parameters.Add(new NpgsqlParameter<DateTimeOffset>("from", NpgsqlDbType.TimestampTz)
            {
                TypedValue = from.ToUniversalTime(),
            });
            command.Parameters.Add(new NpgsqlParameter<DateTimeOffset>("to", NpgsqlDbType.TimestampTz)
            {
                TypedValue = to.ToUniversalTime(),
            });

            var totals = UsageAmounts.Zero;
            var daily = new List<UsageDayAmounts>();

            await using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var amounts = new UsageAmounts(
                    reader.GetInt64(1),
                    reader.GetInt64(2),
                    reader.GetInt64(3),
                    reader.GetInt64(4),
                    reader.GetInt64(5));

                if (await reader.IsDBNullAsync(0, ct))
                {
                    totals = amounts;
                }
                else
                {
                    daily.Add(new UsageDayAmounts(reader.GetFieldValue<DateOnly>(0), amounts));
                }
            }

            return new UsageAggregate(totals, daily);
        }, cancellationToken);
    }

    /// <summary>
    /// DbContext ulanishida, uning retry strategiyasi ostida bajaradi. Ikkala
    /// amal ham qayta bajarilishi xavfsiz: qo'shish idempotent, yig'ish — o'qish.
    /// </summary>
    private Task<T> ExecuteAsync<T>(
        Func<NpgsqlConnection, CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        var strategy = db.Database.CreateExecutionStrategy();

        return strategy.ExecuteAsync(async ct =>
        {
            await db.Database.OpenConnectionAsync(ct);
            try
            {
                return await operation((NpgsqlConnection)db.Database.GetDbConnection(), ct);
            }
            finally
            {
                await db.Database.CloseConnectionAsync();
            }
        }, cancellationToken);
    }

    private static NpgsqlParameter Array<T>(string name, NpgsqlDbType elementType, IEnumerable<T> values) =>
        new NpgsqlParameter<T[]>(name, NpgsqlDbType.Array | elementType) { TypedValue = values.ToArray() };
}
