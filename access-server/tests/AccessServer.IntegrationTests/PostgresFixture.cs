using AccessServer.Application.Abstractions;
using AccessServer.Infrastructure;
using AccessServer.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>
/// Har bir test yugurishi uchun alohida baza yaratadi, migratsiyalarni
/// qo'llaydi va oxirida o'chiradi. Testcontainers ishlatilmaydi: bu mashinada
/// docker konteksti masofaviy serverga qaratilgan bo'lishi mumkin, shuning
/// uchun ulanish satri oshkora beriladi.
///
/// Ulanish: CC01_TEST_DB muhit o'zgaruvchisi, aks holda
/// deploy/docker-compose.dev.yml dagi lokal Postgres (`make dev-up`).
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private const string DefaultAdminConnection =
        "Host=127.0.0.1;Port=15432;Database=postgres;Username=cc01;Password=cc01_dev_only";

    private readonly string _databaseName = "cc01_test_" + Guid.NewGuid().ToString("n")[..12];

    private ServiceProvider _services = null!;

    public string ConnectionString { get; private set; } = string.Empty;

    public async Task InitializeAsync()
    {
        var admin = Environment.GetEnvironmentVariable("CC01_TEST_DB") ?? DefaultAdminConnection;

        var builder = new NpgsqlConnectionStringBuilder(admin) { Database = "postgres" };
        await using (var connection = new NpgsqlConnection(builder.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            // Nom o'zimiz generatsiya qilgan guid — in'yeksiya xavfi yo'q,
            // lekin identifikator baribir qo'shtirnoqqa olinadi.
            command.CommandText = $"CREATE DATABASE \"{_databaseName}\"";
            await command.ExecuteNonQueryAsync();
        }

        builder.Database = _databaseName;
        ConnectionString = builder.ConnectionString;

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:SigningKey"] = "test-signing-key-at-least-32-characters-long-0123456789",
                ["Jwt:Issuer"] = "cc01-access-test",
                ["Jwt:Audience"] = "cc01-dashboard-test",
                ["Jwt:LifetimeMinutes"] = "60",
            })
            .Build();

        var collection = new ServiceCollection();
        collection.AddLogging();
        collection
            .AddAccessPersistence(ConnectionString)
            .AddAccessSecurity(configuration)
            .AddDevelopmentEmailSender()
            .AddAccessUseCases();

        // Ro'yxatdan o'tishda yuborilgan tasdiqlash tokenini testda ushlab
        // olish uchun email sender'ni yozib boruvchi bilan almashtiramiz.
        collection.AddSingleton<RecordingEmailSender>();
        collection.AddSingleton<IEmailSender>(sp => sp.GetRequiredService<RecordingEmailSender>());

        _services = collection.BuildServiceProvider();

        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await db.Database.MigrateAsync();
    }

    public AsyncServiceScope CreateScope() => _services.CreateAsyncScope();

    public RecordingEmailSender Emails => _services.GetRequiredService<RecordingEmailSender>();

    public async Task DisposeAsync()
    {
        await _services.DisposeAsync();

        // Pool'dagi ochiq ulanishlar bazani o'chirishga to'sqinlik qiladi.
        NpgsqlConnection.ClearAllPools();

        var builder = new NpgsqlConnectionStringBuilder(ConnectionString) { Database = "postgres" };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"DROP DATABASE IF EXISTS \"{_databaseName}\" WITH (FORCE)";
        await command.ExecuteNonQueryAsync();
    }
}

[CollectionDefinition(Name)]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>
{
    public const string Name = "postgres";
}
