using System.Text.Json;
using AccessServer.Application.Auth;
using AccessServer.Application.Plans;
using AccessServer.Domain.Enums;
using AccessServer.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>ChangePlanHandler — handler darajasida (HTTP qatlami PlanHttpTests'da).</summary>
[Collection(PostgresCollection.Name)]
public sealed class PlanChangeTests(PostgresFixture fixture)
{
    private const string Password = "correct horse battery staple";

    private sealed record Account(int TenantId, string Slug, string Email);

    private static async Task<Account> RegisterAsync(AsyncServiceScope scope)
    {
        var email = $"c{Guid.NewGuid():n}@example.com";
        var registered = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("Aziz Karimov", email, Password, false));

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tenantId = await db.Users
            .Where(u => u.Id == registered.Value.UserId)
            .Select(u => u.TenantId)
            .SingleAsync();

        return new Account(tenantId, registered.Value.TenantSlug, email);
    }

    private static ChangePlanCommand Change(
        string slug,
        string plan,
        DateTimeOffset? periodEnd = null,
        string actor = "aziz",
        string? reason = "test") =>
        new(slug, plan, periodEnd, actor, reason, "127.0.0.1");

    private static Task<int> AuditCountAsync(AccessDbContext db, int tenantId) =>
        db.AuditEvents.CountAsync(a => a.TenantId == tenantId && a.Action == ChangePlanHandler.AuditAction);

    [Fact]
    public async Task Free_to_pro_updates_in_place_and_writes_one_audit()
    {
        await using var scope = fixture.CreateScope();
        var account = await RegisterAsync(scope);
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var before = await db.Subscriptions.AsNoTracking().SingleAsync(s => s.TenantId == account.TenantId);

        var result = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change(account.Slug, "pro", reason: "sinov"));

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.Changed);
        Assert.Equal(PlanCode.Pro, result.Value.Plan);
        Assert.Equal(account.Slug, result.Value.Tenant);

        // Joyida yangilandi: qator bitta va o'sha Id.
        var rows = await db.Subscriptions.AsNoTracking()
            .Include(s => s.Plan)
            .Where(s => s.TenantId == account.TenantId)
            .ToListAsync();
        var row = Assert.Single(rows);
        Assert.Equal(before.Id, row.Id);
        Assert.Equal(PlanCode.Pro, row.Plan.Code);
        Assert.Equal(SubscriptionStatus.Active, row.Status);

        var audit = await db.AuditEvents.AsNoTracking()
            .SingleAsync(a => a.TenantId == account.TenantId && a.Action == ChangePlanHandler.AuditAction);
        Assert.Equal("operator:aziz", audit.Actor);
        Assert.Equal("tenant:" + account.Slug, audit.Target);
        Assert.Equal("127.0.0.1", audit.Ip);

        using var metadata = JsonDocument.Parse(audit.Metadata!);
        Assert.Equal("free", metadata.RootElement.GetProperty("from").GetString());
        Assert.Equal("pro", metadata.RootElement.GetProperty("to").GetString());
        Assert.Equal("sinov", metadata.RootElement.GetProperty("reason").GetString());

        // Shaxsiy ma'lumot auditga tushmaydi.
        Assert.DoesNotContain(account.Email, audit.Metadata!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Aziz Karimov", audit.Metadata!, StringComparison.OrdinalIgnoreCase);

        // Resolver (edge oladigan manba) darhol Pro'ni ko'radi.
        var effective = await scope.ServiceProvider.GetRequiredService<EffectivePlanResolver>()
            .ResolveAsync(account.TenantId);
        Assert.Equal(PlanCode.Pro, effective.Code);
        Assert.Equal(128, effective.Limits.MaxConnectionsPerTunnel);
    }

    [Fact]
    public async Task Same_plan_same_period_is_noop_without_audit()
    {
        await using var scope = fixture.CreateScope();
        var account = await RegisterAsync(scope);
        var handler = scope.ServiceProvider.GetRequiredService<ChangePlanHandler>();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();

        // Yangi tenant allaqachon Free, muddatsiz.
        var free = await handler.HandleAsync(Change(account.Slug, "free"));
        Assert.True(free.IsSuccess);
        Assert.False(free.Value.Changed);
        Assert.Equal(0, await AuditCountAsync(db, account.TenantId));

        // Sub-mikrosekund qism Postgres'da kesiladi — takror baribir no-op.
        var periodEnd = DateTimeOffset.UtcNow.AddDays(30).AddTicks(7);
        var first = await handler.HandleAsync(Change(account.Slug, "pro", periodEnd));
        Assert.True(first.Value.Changed);

        db.ChangeTracker.Clear();
        var second = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change(account.Slug, "pro", periodEnd));
        Assert.True(second.IsSuccess);
        Assert.False(second.Value.Changed);

        Assert.Equal(1, await AuditCountAsync(db, account.TenantId));
    }

    [Theory]
    [InlineData("1")]
    [InlineData("2")]
    [InlineData("Pro,Free")]
    [InlineData("gold")]
    [InlineData("")]
    [InlineData(" pro")]
    [InlineData("pro ")]
    [InlineData("Pro")]
    [InlineData("PRO")]
    public async Task Unknown_plan_rejected(string plan)
    {
        await using var scope = fixture.CreateScope();
        var account = await RegisterAsync(scope);

        var result = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change(account.Slug, plan));

        Assert.False(result.IsSuccess);
        Assert.Equal("PLAN_UNKNOWN", result.Error!.Code);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(0, await AuditCountAsync(db, account.TenantId));
    }

    [Fact]
    public void Plan_code_parser_round_trips_every_code()
    {
        foreach (var code in Enum.GetValues<PlanCode>())
        {
            Assert.True(PlanCodeParser.TryParse(PlanCodeParser.ToWire(code), out var parsed));
            Assert.Equal(code, parsed);
        }

        Assert.False(PlanCodeParser.TryParse(null, out _));
    }

    [Fact]
    public async Task Unknown_tenant_returns_TENANT_NOT_FOUND()
    {
        await using var scope = fixture.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change("t_doesnotexist", "pro"));

        Assert.Equal("TENANT_NOT_FOUND", result.Error!.Code);
    }

    [Fact]
    public async Task Deleted_tenant_returns_TENANT_NOT_FOUND_and_suspended_is_allowed()
    {
        await using var scope = fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var deleted = await RegisterAsync(scope);
        var suspended = await RegisterAsync(scope);

        await db.Tenants.Where(t => t.Id == deleted.TenantId)
            .ExecuteUpdateAsync(u => u.SetProperty(t => t.Status, TenantStatus.Deleted));
        await db.Tenants.Where(t => t.Id == suspended.TenantId)
            .ExecuteUpdateAsync(u => u.SetProperty(t => t.Status, TenantStatus.Suspended));

        // Ro'yxatdan o'tishda kuzatilgan eski qiymatlar xom yangilanishni yashirmasin.
        db.ChangeTracker.Clear();

        var handler = scope.ServiceProvider.GetRequiredService<ChangePlanHandler>();

        var onDeleted = await handler.HandleAsync(Change(deleted.Slug, "pro"));
        Assert.Equal("TENANT_NOT_FOUND", onDeleted.Error!.Code);

        // To'xtatish va tarif mustaqil: tarifni o'zgartirish mumkin, tunnel
        // esa baribir PLAN_SUSPENDED oladi.
        var onSuspended = await handler.HandleAsync(Change(suspended.Slug, "pro"));
        Assert.True(onSuspended.IsSuccess);
    }

    [Fact]
    public async Task Past_period_returns_PLAN_PERIOD_INVALID()
    {
        await using var scope = fixture.CreateScope();
        var account = await RegisterAsync(scope);

        var result = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change(account.Slug, "pro", DateTimeOffset.UtcNow.AddMinutes(-1)));

        Assert.Equal("PLAN_PERIOD_INVALID", result.Error!.Code);
    }

    [Theory]
    [InlineData("")]
    [InlineData("aziz@example.com")]
    [InlineData("has space")]
    [InlineData("a\nb")]
    [InlineData("aziz\n")] // .NET'da `$` oxirgi \n dan oldin ham mos keladi
    [InlineData("aziz\r\n")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")] // 56
    public async Task Invalid_actor_returns_PLAN_ACTOR_INVALID(string actor)
    {
        await using var scope = fixture.CreateScope();
        var account = await RegisterAsync(scope);

        var result = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change(account.Slug, "pro", actor: actor));

        Assert.Equal("PLAN_ACTOR_INVALID", result.Error!.Code);
    }

    [Fact]
    public async Task Longest_allowed_actor_fits_audit_column()
    {
        await using var scope = fixture.CreateScope();
        var account = await RegisterAsync(scope);

        var result = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change(account.Slug, "pro", actor: new string('a', ChangePlanHandler.MaxActorLength)));

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task Too_long_reason_returns_PLAN_REASON_INVALID()
    {
        await using var scope = fixture.CreateScope();
        var account = await RegisterAsync(scope);

        var result = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change(account.Slug, "pro", reason: new string('x', ChangePlanHandler.MaxReasonLength + 1)));

        Assert.Equal("PLAN_REASON_INVALID", result.Error!.Code);
    }

    /// <summary>
    /// Indeks orqali: NUL va juftsiz surrogat xUnit test nomida/serializatsiyada
    /// muammo tug'dirmasin.
    /// </summary>
    private static readonly string[] BadReasons =
    [
        "a\u0000b", // jsonb rad etadi (22P05) — avval 409 "qayta urining" edi
        "qator\nqator",
        "tab\tbilan",
        "\u001b[31mqizil",
        "juftsiz \ud800 surrogat",
        "\udc00",
        "oxirida\ud83d",
    ];

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    public async Task Control_characters_in_reason_return_PLAN_REASON_INVALID(int index)
    {
        await using var scope = fixture.CreateScope();
        var account = await RegisterAsync(scope);
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();

        var result = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change(account.Slug, "pro", reason: BadReasons[index]));

        Assert.Equal("PLAN_REASON_INVALID", result.Error!.Code);
        Assert.Equal(0, await AuditCountAsync(db, account.TenantId));
    }

    [Fact]
    public async Task Unicode_reason_with_surrogate_pairs_is_accepted()
    {
        await using var scope = fixture.CreateScope();
        var account = await RegisterAsync(scope);

        var result = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change(account.Slug, "pro", reason: "O'zbekcha sabab — ✓ 😀"));

        Assert.True(result.IsSuccess);
    }

    /// <summary>
    /// Faqat haqiqiy poyga (xmin yoki unique indeks) 409 bo'ladi. Qolgan
    /// DbUpdateException'lar qayta urinish bilan tuzalmaydi — ular yuqoriga
    /// ko'tariladi (HTTP'da 500), "qayta urinib ko'ring" deb yashirilmaydi.
    /// </summary>
    [Theory]
    [InlineData("concurrency", true)]
    [InlineData("23505", true)]
    [InlineData("22P05", false)]
    [InlineData("23503", false)]
    [InlineData("none", false)]
    public async Task Only_concurrency_and_unique_violation_map_to_conflict(string failure, bool conflict)
    {
        Account account;
        await using (var scope = fixture.CreateScope())
        {
            account = await RegisterAsync(scope);
        }

        var options = new DbContextOptionsBuilder<AccessDbContext>()
            .UseNpgsql(fixture.ConnectionString)
            .UseSnakeCaseNamingConvention()
            .AddInterceptors(new FailingSave(failure))
            .Options;

        await using var db = new AccessDbContext(options, TimeProvider.System);
        var handler = new ChangePlanHandler(db, TimeProvider.System, NullLogger<ChangePlanHandler>.Instance);

        if (conflict)
        {
            var result = await handler.HandleAsync(Change(account.Slug, "pro"));
            Assert.Equal("SUBSCRIPTION_CONFLICT", result.Error!.Code);
        }
        else
        {
            await Assert.ThrowsAsync<DbUpdateException>(() => handler.HandleAsync(Change(account.Slug, "pro")));
        }
    }

    private sealed class FailingSave(string failure) : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default) =>
            throw (failure switch
            {
                "concurrency" => new DbUpdateConcurrencyException("xmin o'zgargan"),
                "none" => new DbUpdateException("ichki xatosiz"),
                _ => new DbUpdateException(
                    "baza xatosi",
                    new Npgsql.PostgresException("sinov", "ERROR", "ERROR", failure)),
            });
    }

    [Fact]
    public async Task Tenant_without_subscription_gets_row_created()
    {
        await using var scope = fixture.CreateScope();
        var account = await RegisterAsync(scope);
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await db.Subscriptions.Where(s => s.TenantId == account.TenantId).ExecuteDeleteAsync();
        db.ChangeTracker.Clear();

        var result = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(Change(account.Slug, "enterprise"));

        Assert.True(result.Value.Changed);
        var row = await db.Subscriptions.AsNoTracking().Include(s => s.Plan)
            .SingleAsync(s => s.TenantId == account.TenantId);
        Assert.Equal(PlanCode.Enterprise, row.Plan.Code);

        var audit = await db.AuditEvents.AsNoTracking()
            .SingleAsync(a => a.TenantId == account.TenantId && a.Action == ChangePlanHandler.AuditAction);
        using var metadata = JsonDocument.Parse(audit.Metadata!);
        Assert.Equal(JsonValueKind.Null, metadata.RootElement.GetProperty("from").ValueKind);
    }

    [Fact]
    public async Task Concurrent_plan_changes_one_conflicts()
    {
        Account account;
        await using (var scope = fixture.CreateScope())
        {
            account = await RegisterAsync(scope);
        }

        var outcomes = await RunConcurrentlyAsync(account.Slug, "pro", "enterprise");

        Assert.Single(outcomes, r => r.IsSuccess);
        Assert.Single(outcomes, r => r.Error?.Code == "SUBSCRIPTION_CONFLICT");

        await using var check = PostgresFixture.CreateContext(fixture.ConnectionString);
        Assert.Equal(1, await check.Subscriptions.CountAsync(s => s.TenantId == account.TenantId));

        // Yutqazgan tomonning audit yozuvi ham tranzaksiya bilan birga qaytarildi.
        Assert.Equal(1, await AuditCountAsync(check, account.TenantId));
    }

    [Fact]
    public async Task Concurrent_first_subscription_inserts_one_conflicts()
    {
        Account account;
        await using (var scope = fixture.CreateScope())
        {
            account = await RegisterAsync(scope);
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            await db.Subscriptions.Where(s => s.TenantId == account.TenantId).ExecuteDeleteAsync();
        }

        var outcomes = await RunConcurrentlyAsync(account.Slug, "pro", "enterprise");

        Assert.Single(outcomes, r => r.IsSuccess);
        Assert.Single(outcomes, r => r.Error?.Code == "SUBSCRIPTION_CONFLICT");

        await using var check = PostgresFixture.CreateContext(fixture.ConnectionString);
        Assert.Equal(1, await check.Subscriptions.CountAsync(s => s.TenantId == account.TenantId));
        Assert.Equal(1, await AuditCountAsync(check, account.TenantId));
    }

    /// <summary>
    /// Ikki handler, ikki alohida kontekst. Ikkalasi ham o'qishni tugatib
    /// SaveChanges'ga yetmaguncha hech biri yozmaydi (to'siq) — shunda
    /// poyga tasodifga emas, aniq tartibga bog'liq.
    /// </summary>
    private async Task<Application.Common.Result<SubscriptionView>[]> RunConcurrentlyAsync(
        string slug, string planA, string planB)
    {
        var barrier = new SaveBarrier(participants: 2);
        var options = new DbContextOptionsBuilder<AccessDbContext>()
            .UseNpgsql(fixture.ConnectionString)
            .UseSnakeCaseNamingConvention()
            .AddInterceptors(barrier)
            .Options;

        await using var first = new AccessDbContext(options, TimeProvider.System);
        await using var second = new AccessDbContext(options, TimeProvider.System);

        var a = new ChangePlanHandler(first, TimeProvider.System, NullLogger<ChangePlanHandler>.Instance)
            .HandleAsync(Change(slug, planA));
        var b = new ChangePlanHandler(second, TimeProvider.System, NullLogger<ChangePlanHandler>.Instance)
            .HandleAsync(Change(slug, planB));

        return await Task.WhenAll(a, b);
    }

    private sealed class SaveBarrier(int participants) : SaveChangesInterceptor
    {
        private readonly TaskCompletionSource _released =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private int _arrived;

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _arrived) == participants)
            {
                _released.SetResult();
            }

            await _released.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
            return result;
        }
    }
}
