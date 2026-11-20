using AccessServer.Application.Auth;
using AccessServer.Application.Plans;
using AccessServer.Domain.Entities;
using AccessServer.Domain.Enums;
using AccessServer.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AccessServer.IntegrationTests;

[Collection(PostgresCollection.Name)]
public sealed class EffectivePlanResolverTests(PostgresFixture fixture)
{
    private const string Password = "correct horse battery staple";

    private static string UniqueEmail() => $"p{Guid.NewGuid():n}@example.com";

    private static async Task<int> RegisterAsync(AsyncServiceScope scope)
    {
        var registered = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("A", UniqueEmail(), Password, false));

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        return await db.Users
            .Where(u => u.Id == registered.Value.UserId)
            .Select(u => u.TenantId)
            .SingleAsync();
    }

    /// <summary>Obuna qatorini to'g'ridan-to'g'ri o'zgartiradi (ChangePlanHandler'siz).</summary>
    private static async Task SetSubscriptionAsync(
        AccessDbContext db,
        int tenantId,
        PlanCode plan,
        SubscriptionStatus status = SubscriptionStatus.Active,
        DateTimeOffset? periodStart = null,
        DateTimeOffset? periodEnd = null)
    {
        var subscription = await db.Subscriptions.SingleAsync(s => s.TenantId == tenantId);
        subscription.PlanId = (await db.Plans.SingleAsync(p => p.Code == plan)).Id;
        subscription.Status = status;
        subscription.PeriodStart = periodStart ?? subscription.PeriodStart;
        subscription.PeriodEnd = periodEnd;
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task New_tenants_start_on_active_free_subscription()
    {
        await using var scope = fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();

        var registeredTenantId = await RegisterAsync(scope);

        var email = UniqueEmail();
        var oauth = await scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>()
            .HandleAsync(new OAuthLoginCommand(
                OAuthProvider.Github, Guid.NewGuid().ToString("n"), email, EmailVerified: true, "B"));
        Assert.True(oauth.IsSuccess);
        var oauthTenantId = await db.Users.Where(u => u.Email == email).Select(u => u.TenantId).SingleAsync();

        foreach (var tenantId in new[] { registeredTenantId, oauthTenantId })
        {
            var subscription = await db.Subscriptions
                .AsNoTracking()
                .Include(s => s.Plan)
                .SingleAsync(s => s.TenantId == tenantId);

            Assert.Equal(PlanCode.Free, subscription.Plan.Code);
            Assert.Equal(SubscriptionStatus.Active, subscription.Status);
            Assert.Null(subscription.PeriodEnd);
        }
    }

    [Fact]
    public async Task Active_pro_resolves_pro()
    {
        await using var scope = fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tenantId = await RegisterAsync(scope);

        await SetSubscriptionAsync(db, tenantId, PlanCode.Pro,
            periodEnd: DateTimeOffset.UtcNow.AddDays(30));

        var plan = await scope.ServiceProvider.GetRequiredService<EffectivePlanResolver>()
            .ResolveAsync(tenantId);

        Assert.Equal(PlanCode.Pro, plan.Code);
        Assert.Equal(EffectivePlanSource.Subscription, plan.Source);
        Assert.Equal(new PlanLimits(10, 10, 128, 1_000_000_000), plan.Limits);
    }

    [Fact]
    public async Task Expired_period_falls_back_to_free()
    {
        await using var scope = fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tenantId = await RegisterAsync(scope);
        var now = DateTimeOffset.UtcNow;

        await SetSubscriptionAsync(db, tenantId, PlanCode.Pro,
            periodStart: now.AddDays(-31), periodEnd: now.AddMinutes(-1));

        var plan = await scope.ServiceProvider.GetRequiredService<EffectivePlanResolver>()
            .ResolveAsync(tenantId);

        Assert.Equal(PlanCode.Free, plan.Code);
        Assert.Equal(EffectivePlanSource.Expired, plan.Source);
        Assert.Equal(24, plan.Limits.MaxConnectionsPerTunnel);
    }

    [Fact]
    public async Task Canceled_falls_back_to_free()
    {
        await using var scope = fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tenantId = await RegisterAsync(scope);

        await SetSubscriptionAsync(db, tenantId, PlanCode.Enterprise, SubscriptionStatus.Canceled);

        var plan = await scope.ServiceProvider.GetRequiredService<EffectivePlanResolver>()
            .ResolveAsync(tenantId);

        Assert.Equal(PlanCode.Free, plan.Code);
        Assert.Equal(EffectivePlanSource.Canceled, plan.Source);
    }

    [Fact]
    public async Task Missing_subscription_falls_back_to_free()
    {
        await using var scope = fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();

        var tenant = new Tenant { Slug = "t_" + Guid.NewGuid().ToString("n")[..12], Name = "N" };
        db.Tenants.Add(tenant);
        await db.SaveChangesAsync();

        var plan = await scope.ServiceProvider.GetRequiredService<EffectivePlanResolver>()
            .ResolveAsync(tenant.Id);

        Assert.Equal(PlanCode.Free, plan.Code);
        Assert.Equal(EffectivePlanSource.NoSubscription, plan.Source);
        Assert.Equal(new PlanLimits(1, 1, 24, 100_000_000), plan.Limits);
    }

    /// <summary>
    /// Katalog yagona manba: jadvaldagi tahrir keyingi chaqiruvda — hatto
    /// shu kontekst qatorni oldin o'qigan bo'lsa ham — ko'rinadi. Umumiy
    /// bazani buzmaslik uchun alohida bazada.
    /// </summary>
    [Fact]
    public async Task Catalog_edit_is_visible_immediately()
    {
        var connectionString = await fixture.CreateScratchDatabaseAsync();
        try
        {
            await using var db = PostgresFixture.CreateContext(connectionString);
            await db.Database.MigrateAsync();

            var pro = await db.Plans.SingleAsync(p => p.Code == PlanCode.Pro);
            var tenant = new Tenant
            {
                Slug = "t_catalog",
                Name = "C",
                Subscription = new Subscription { Plan = pro, PeriodStart = DateTimeOffset.UtcNow },
            };
            db.Tenants.Add(tenant);
            await db.SaveChangesAsync();

            var resolver = new EffectivePlanResolver(db, TimeProvider.System);
            Assert.Equal(128, (await resolver.ResolveAsync(tenant.Id)).Limits.MaxConnectionsPerTunnel);

            await db.Database.ExecuteSqlRawAsync(
                "UPDATE plans SET max_conns_per_tunnel = 200 WHERE code = 'Pro'");

            Assert.Equal(200, (await resolver.ResolveAsync(tenant.Id)).Limits.MaxConnectionsPerTunnel);
        }
        finally
        {
            await PostgresFixture.DropScratchDatabaseAsync(connectionString);
        }
    }

    [Fact]
    public async Task Missing_free_row_throws()
    {
        var connectionString = await fixture.CreateScratchDatabaseAsync();
        try
        {
            await using var db = PostgresFixture.CreateContext(connectionString);
            await db.Database.MigrateAsync();

            var tenant = new Tenant { Slug = "t_nofree", Name = "N" };
            db.Tenants.Add(tenant);
            await db.SaveChangesAsync();

            await db.Database.ExecuteSqlRawAsync("DELETE FROM plans WHERE code = 'Free'");

            // Kod ichida zaxira yo'q — jim "Free 24" o'rniga aniq xato.
            var resolver = new EffectivePlanResolver(db, TimeProvider.System);
            await Assert.ThrowsAsync<InvalidOperationException>(() => resolver.ResolveAsync(tenant.Id));
            await Assert.ThrowsAsync<InvalidOperationException>(() => db.GetFreePlanAsync());
        }
        finally
        {
            await PostgresFixture.DropScratchDatabaseAsync(connectionString);
        }
    }
}
