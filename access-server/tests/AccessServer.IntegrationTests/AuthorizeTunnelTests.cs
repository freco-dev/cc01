using AccessServer.Application.Auth;
using AccessServer.Application.Common;
using AccessServer.Application.Plans;
using AccessServer.Application.Subdomains;
using AccessServer.Application.Tokens;
using AccessServer.Application.Tunnels;
using AccessServer.Domain.Enums;
using AccessServer.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AccessServer.IntegrationTests;

[Collection(PostgresCollection.Name)]
public sealed class AuthorizeTunnelTests(PostgresFixture fixture)
{
    private const string Password = "correct horse battery staple";

    private sealed record Account(int UserId, int TenantId, string Token);

    private async Task<Account> CreateAccountWithTokenAsync(AsyncServiceScope scope)
    {
        var email = $"t{Guid.NewGuid():n}@example.com";

        var registered = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("A", email, Password, false));

        await scope.ServiceProvider.GetRequiredService<VerifyEmailHandler>()
            .HandleAsync(new VerifyEmailCommand(fixture.Emails.TokenFor(email)));

        var token = await scope.ServiceProvider.GetRequiredService<CreateApiTokenHandler>()
            .HandleAsync(new CreateApiTokenCommand(registered.Value.UserId, "cli", null));

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var user = await db.Users.SingleAsync(u => u.Id == registered.Value.UserId);

        return new Account(user.Id, user.TenantId, token.Value.Secret);
    }

    private static string UniqueName() => "app" + Guid.NewGuid().ToString("n")[..10];

    [Fact]
    public async Task Valid_token_with_free_name_reserves_and_grants()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);
        var name = UniqueName();

        var result = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, name, null, "0.1.0", "127.0.0.1"));

        Assert.True(result.IsSuccess);
        Assert.Equal(name, result.Value.Subdomain);
        Assert.Equal(PlanCode.Free, result.Value.Plan);

        // Free tarif limiti core-server'dagi qattiq 24 ning o'rniga keladi.
        Assert.Equal(24, result.Value.Limits.MaxConnectionsPerTunnel);

        // Nom shu yerda EGALIK qilinadi — keyingi safar boshqa hisob ololmaydi.
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var subdomain = await db.Subdomains.SingleAsync(s => s.Name == name);
        Assert.Equal(account.TenantId, subdomain.TenantId);
    }

    [Fact]
    public async Task Token_last_used_is_recorded()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);

        await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, UniqueName(), null, null, null));

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var token = await db.ApiTokens.SingleAsync(t => t.TenantId == account.TenantId);

        Assert.NotNull(token.LastUsedAt);
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("cc01_live_deadbeef_notarealsecretvalue")]
    public async Task Bad_token_is_denied(string token)
    {
        await using var scope = fixture.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(token, UniqueName(), null, null, null));

        Assert.Equal(nameof(TunnelDenial.TokenInvalid), result.Error!.Code);
    }

    [Fact]
    public async Task Revoked_token_is_denied()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var token = await db.ApiTokens.SingleAsync(t => t.TenantId == account.TenantId);

        await scope.ServiceProvider.GetRequiredService<RevokeApiTokenHandler>()
            .HandleAsync(new RevokeApiTokenCommand(account.TenantId, token.Id));

        var result = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, UniqueName(), null, null, null));

        Assert.Equal(nameof(TunnelDenial.TokenRevoked), result.Error!.Code);
    }

    [Fact]
    public async Task Expired_token_is_denied()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var token = await db.ApiTokens.SingleAsync(t => t.TenantId == account.TenantId);
        token.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        await db.SaveChangesAsync();

        var result = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, UniqueName(), null, null, null));

        Assert.Equal(nameof(TunnelDenial.TokenExpired), result.Error!.Code);
    }

    [Fact]
    public async Task Suspended_tenant_is_denied()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tenant = await db.Tenants.SingleAsync(t => t.Id == account.TenantId);
        tenant.Status = TenantStatus.Suspended;
        await db.SaveChangesAsync();

        var result = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, UniqueName(), null, null, null));

        Assert.Equal(nameof(TunnelDenial.PlanSuspended), result.Error!.Code);
    }

    /// <summary>
    /// Loyihaning asosiy va'dasi: subdomain "birinchi kelgan oladi" emas,
    /// EGALIK qilinadi. Bu core-server'ning eski xatti-harakatidan farqi.
    /// </summary>
    [Fact]
    public async Task Subdomain_owned_by_another_tenant_is_denied()
    {
        await using var scope = fixture.CreateScope();
        var owner = await CreateAccountWithTokenAsync(scope);
        var stranger = await CreateAccountWithTokenAsync(scope);
        var name = UniqueName();

        var handler = scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>();

        Assert.True((await handler.HandleAsync(
            new AuthorizeTunnelCommand(owner.Token, name, null, null, null))).IsSuccess);

        var result = await handler.HandleAsync(
            new AuthorizeTunnelCommand(stranger.Token, name, null, null, null));

        Assert.Equal(nameof(TunnelDenial.SubdomainNotOwned), result.Error!.Code);
    }

    [Fact]
    public async Task Owner_can_reopen_the_same_subdomain()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);
        var name = UniqueName();
        var handler = scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>();

        await handler.HandleAsync(new AuthorizeTunnelCommand(account.Token, name, null, null, null));
        var again = await handler.HandleAsync(new AuthorizeTunnelCommand(account.Token, name, null, null, null));

        Assert.True(again.IsSuccess);
        Assert.Equal(name, again.Value.Subdomain);
    }

    [Theory]
    [InlineData("ab")]
    [InlineData("-bad")]
    [InlineData("a--b")]
    [InlineData("www")]
    public async Task Invalid_subdomain_is_denied(string name)
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);

        var result = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, name, null, null, null));

        Assert.Equal(nameof(TunnelDenial.SubdomainInvalid), result.Error!.Code);
    }

    [Fact]
    public async Task Empty_subdomain_falls_back_to_owned_one()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);
        var name = UniqueName();

        await scope.ServiceProvider.GetRequiredService<ReserveSubdomainHandler>()
            .HandleAsync(new ReserveSubdomainCommand(account.TenantId, name));

        var result = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, Subdomain: null, null, null, null));

        Assert.True(result.IsSuccess);
        Assert.Equal(name, result.Value.Subdomain);
    }

    [Fact]
    public async Task Empty_subdomain_without_any_reservation_is_denied()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);

        var result = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, Subdomain: null, null, null, null));

        Assert.Equal(nameof(TunnelDenial.SubdomainNotOwned), result.Error!.Code);
    }

    [Fact]
    public async Task Free_plan_quota_blocks_a_second_name()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);
        var handler = scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>();

        Assert.True((await handler.HandleAsync(
            new AuthorizeTunnelCommand(account.Token, UniqueName(), null, null, null))).IsSuccess);

        var second = await handler.HandleAsync(
            new AuthorizeTunnelCommand(account.Token, UniqueName(), null, null, null));

        Assert.Equal(nameof(TunnelDenial.QuotaTunnelsExceeded), second.Error!.Code);
    }

    [Fact]
    public async Task Pro_plan_gets_higher_connection_limit()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);
        await ChangePlanAsync(scope, account.TenantId, "pro");

        var result = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, UniqueName(), null, null, null));

        Assert.True(result.IsSuccess);
        Assert.Equal(128, result.Value.Limits.MaxConnectionsPerTunnel);
        Assert.Equal(PlanCode.Pro, result.Value.Plan);
    }

    [Fact]
    public async Task Plan_change_is_visible_on_next_authorize()
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);
        var name = UniqueName();
        var authorize = scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>();

        var before = await authorize.HandleAsync(
            new AuthorizeTunnelCommand(account.Token, name, null, null, null));
        Assert.Equal(24, before.Value.Limits.MaxConnectionsPerTunnel);

        await ChangePlanAsync(scope, account.TenantId, "pro");

        // Ayni bir scope (va DbContext) — kesh yoki kuzatilgan qator eski
        // qiymatni qaytarmasligi kerak.
        var after = await authorize.HandleAsync(
            new AuthorizeTunnelCommand(account.Token, name, null, null, null));
        Assert.Equal(PlanCode.Pro, after.Value.Plan);
        Assert.Equal(128, after.Value.Limits.MaxConnectionsPerTunnel);
    }

    // ───────────────────── Lease yangilanishi (renewal) ─────────────────────

    private async Task<Result<AuthorizeTunnelGrant>> RenewAsync(string token, string? name)
    {
        // Har yangilanish alohida scope'da — productiondagi kabi so'rov
        // boshiga yangi DbContext, kuzatilgan eski qatorlar aralashmaydi.
        await using var scope = fixture.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(token, name, null, "0.1.0", "127.0.0.1", IsRenewal: true));
    }

    private async Task<Account> CreateAccountWithOpenTunnelAsync(string name)
    {
        await using var scope = fixture.CreateScope();
        var account = await CreateAccountWithTokenAsync(scope);

        var opened = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, name, null, null, null));
        Assert.True(opened.IsSuccess);

        return account;
    }

    private async Task<DateTimeOffset?> LastUsedAtAsync(int tenantId)
    {
        await using var scope = fixture.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AccessDbContext>().ApiTokens
            .AsNoTracking()
            .Where(t => t.TenantId == tenantId)
            .Select(t => t.LastUsedAt)
            .SingleAsync();
    }

    private async Task SetLastUsedAtAsync(int tenantId, DateTimeOffset? value)
    {
        await using var scope = fixture.CreateScope();
        await scope.ServiceProvider.GetRequiredService<AccessDbContext>().ApiTokens
            .Where(t => t.TenantId == tenantId)
            .ExecuteUpdateAsync(u => u.SetProperty(t => t.LastUsedAt, value));
    }

    /// <summary>Soniyagacha yaxlitlangan — timestamptz aylanishida aniqlik yo'qolmasin.</summary>
    private static DateTimeOffset SecondsAgo(int seconds)
    {
        var now = DateTimeOffset.UtcNow;
        return new DateTimeOffset(now.Ticks - now.Ticks % TimeSpan.TicksPerSecond, TimeSpan.Zero)
            .AddSeconds(-seconds);
    }

    [Fact]
    public async Task Renewal_of_owned_name_grants_current_limits()
    {
        var name = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(name);

        var renewed = await RenewAsync(account.Token, name);

        Assert.True(renewed.IsSuccess);
        Assert.Equal(name, renewed.Value.Subdomain);
        Assert.Equal(PlanCode.Free, renewed.Value.Plan);
        Assert.Equal(24, renewed.Value.Limits.MaxConnectionsPerTunnel);
        Assert.Equal(AuthorizeTunnelHandler.LeaseTtlSeconds, renewed.Value.LeaseTtlSeconds);
    }

    [Fact]
    public async Task Renewal_reflects_plan_change_immediately()
    {
        var name = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(name);

        Assert.Equal(24, (await RenewAsync(account.Token, name)).Value.Limits.MaxConnectionsPerTunnel);

        await using (var scope = fixture.CreateScope())
        {
            await ChangePlanAsync(scope, account.TenantId, "pro");
        }

        var renewed = await RenewAsync(account.Token, name);
        Assert.True(renewed.IsSuccess);
        Assert.Equal(PlanCode.Pro, renewed.Value.Plan);
        Assert.Equal(128, renewed.Value.Limits.MaxConnectionsPerTunnel);

        await using (var scope = fixture.CreateScope())
        {
            await ChangePlanAsync(scope, account.TenantId, "free");
        }

        Assert.Equal(24, (await RenewAsync(account.Token, name)).Value.Limits.MaxConnectionsPerTunnel);
    }

    [Fact]
    public async Task Renewal_never_reserves_unknown_name()
    {
        Account account;
        await using (var scope = fixture.CreateScope())
        {
            account = await CreateAccountWithTokenAsync(scope);
        }

        var name = UniqueName();
        var renewed = await RenewAsync(account.Token, name);

        Assert.Equal(nameof(TunnelDenial.SubdomainNotOwned), renewed.Error!.Code);

        await using var verify = fixture.CreateScope();
        var db = verify.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.False(await db.Subdomains.AnyAsync(s => s.Name == name));
        Assert.False(await db.Subdomains.AnyAsync(s => s.TenantId == account.TenantId));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Renewal_without_subdomain_is_denied(string? name)
    {
        // Ochilishdagi "mavjud nomni tanlash" fallback'i yangilanishda yo'q:
        // edge BERILGAN nomni yuborishi shart.
        var owned = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(owned);

        var renewed = await RenewAsync(account.Token, name);

        Assert.Equal(nameof(TunnelDenial.SubdomainNotOwned), renewed.Error!.Code);
    }

    [Fact]
    public async Task Renewal_normalizes_name_like_open()
    {
        var name = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(name);

        var renewed = await RenewAsync(account.Token, "  " + name.ToUpperInvariant() + " ");

        Assert.True(renewed.IsSuccess);
        Assert.Equal(name, renewed.Value.Subdomain);
    }

    [Fact]
    public async Task Renewal_denies_released_name()
    {
        var name = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(name);

        await using (var scope = fixture.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var subdomainId = await db.Subdomains.Where(s => s.Name == name).Select(s => s.Id).SingleAsync();

            var released = await scope.ServiceProvider.GetRequiredService<ReleaseSubdomainHandler>()
                .HandleAsync(new ReleaseSubdomainCommand(account.TenantId, subdomainId));
            Assert.True(released.IsSuccess);
        }

        var renewed = await RenewAsync(account.Token, name);

        Assert.Equal(nameof(TunnelDenial.SubdomainNotOwned), renewed.Error!.Code);
    }

    private async Task ReleaseAsync(int tenantId, string name)
    {
        await using var scope = fixture.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var subdomainId = await db.Subdomains.Where(s => s.Name == name).Select(s => s.Id).SingleAsync();

        var released = await scope.ServiceProvider.GetRequiredService<ReleaseSubdomainHandler>()
            .HandleAsync(new ReleaseSubdomainCommand(tenantId, subdomainId));
        Assert.True(released.IsSuccess);
    }

    private async Task<Result<AuthorizeTunnelGrant>> OpenAsync(string token, string? name)
    {
        await using var scope = fixture.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(token, name, null, "0.1.0", "127.0.0.1"));
    }

    private async Task<SubdomainStatus> SubdomainStatusAsync(string name)
    {
        await using var scope = fixture.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AccessDbContext>().Subdomains
            .AsNoTracking()
            .Where(s => s.Name == name)
            .Select(s => s.Status)
            .SingleAsync();
    }

    [Fact]
    public async Task Open_of_own_released_name_reclaims_it_and_renewal_keeps_tunnel()
    {
        // Ochilish va yangilanish bir xil egalik qoidasiga amal qilishi shart:
        // aks holda tunnel ochiladi va birinchi yangilanishda yopiladi.
        var name = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(name);
        await ReleaseAsync(account.TenantId, name);

        var reopened = await OpenAsync(account.Token, name);

        Assert.True(reopened.IsSuccess);
        Assert.Equal(name, reopened.Value.Subdomain);
        Assert.Equal(SubdomainStatus.Reserved, await SubdomainStatusAsync(name));

        var renewed = await RenewAsync(account.Token, name);

        Assert.True(renewed.IsSuccess);
        Assert.Equal(name, renewed.Value.Subdomain);
    }

    [Fact]
    public async Task Open_of_own_released_name_counts_quota()
    {
        // Free: 1 nom. Bo'shatilgan nom o'rniga boshqasi olingan — eskisini
        // qaytarish kvotani oshirardi, shuning uchun rad etiladi va nom
        // `Released` qoladi (yangilanish ham uni bermaydi).
        var released = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(released);
        await ReleaseAsync(account.TenantId, released);

        var other = UniqueName();
        Assert.True((await OpenAsync(account.Token, other)).IsSuccess);

        var reopened = await OpenAsync(account.Token, released);

        Assert.Equal(nameof(TunnelDenial.QuotaTunnelsExceeded), reopened.Error!.Code);
        Assert.Equal(SubdomainStatus.Released, await SubdomainStatusAsync(released));
        Assert.Equal(nameof(TunnelDenial.SubdomainNotOwned), (await RenewAsync(account.Token, released)).Error!.Code);
    }

    [Fact]
    public async Task Renewal_denies_other_tenants_name()
    {
        var name = UniqueName();
        await CreateAccountWithOpenTunnelAsync(name);

        Account stranger;
        await using (var scope = fixture.CreateScope())
        {
            stranger = await CreateAccountWithTokenAsync(scope);
        }

        var renewed = await RenewAsync(stranger.Token, name);

        Assert.Equal(nameof(TunnelDenial.SubdomainNotOwned), renewed.Error!.Code);
    }

    [Fact]
    public async Task Renewal_denied_after_token_revoked()
    {
        var name = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(name);

        await using (var scope = fixture.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var tokenId = await db.ApiTokens.Where(t => t.TenantId == account.TenantId).Select(t => t.Id).SingleAsync();

            await scope.ServiceProvider.GetRequiredService<RevokeApiTokenHandler>()
                .HandleAsync(new RevokeApiTokenCommand(account.TenantId, tokenId));
        }

        var renewed = await RenewAsync(account.Token, name);

        Assert.Equal(nameof(TunnelDenial.TokenRevoked), renewed.Error!.Code);
    }

    [Fact]
    public async Task Renewal_denied_when_tenant_suspended()
    {
        var name = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(name);

        await using (var scope = fixture.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<AccessDbContext>().Tenants
                .Where(t => t.Id == account.TenantId)
                .ExecuteUpdateAsync(u => u.SetProperty(t => t.Status, TenantStatus.Suspended));
        }

        var renewed = await RenewAsync(account.Token, name);

        Assert.Equal(nameof(TunnelDenial.PlanSuspended), renewed.Error!.Code);
    }

    [Fact]
    public async Task Renewal_does_not_count_subdomain_quota()
    {
        // Pro'da ikki nom, keyin Free'ga (1 nom) tushiriladi. Yangilanish
        // kvotani sanamaydi: eng eski nom (ochilishdagi "owns >= max" bo'lsa
        // rad etilardi) baribir Free limitlari bilan yangilanadi.
        var first = UniqueName();
        var second = UniqueName();
        Account account;

        await using (var scope = fixture.CreateScope())
        {
            account = await CreateAccountWithTokenAsync(scope);
            await ChangePlanAsync(scope, account.TenantId, "pro");

            var authorize = scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>();
            Assert.True((await authorize.HandleAsync(new AuthorizeTunnelCommand(account.Token, first, null, null, null))).IsSuccess);
            Assert.True((await authorize.HandleAsync(new AuthorizeTunnelCommand(account.Token, second, null, null, null))).IsSuccess);

            await ChangePlanAsync(scope, account.TenantId, "free");
        }

        var renewed = await RenewAsync(account.Token, first);

        Assert.True(renewed.IsSuccess);
        Assert.Equal(PlanCode.Free, renewed.Value.Plan);
        Assert.Equal(24, renewed.Value.Limits.MaxConnectionsPerTunnel);

        await using var verify = fixture.CreateScope();
        Assert.Equal(2, await verify.ServiceProvider.GetRequiredService<AccessDbContext>().Subdomains
            .CountAsync(s => s.TenantId == account.TenantId));
    }

    [Fact]
    public async Task Renewal_skips_last_used_write_within_5_minutes()
    {
        var name = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(name);

        // 2 daqiqa oldin ishlatilgan — yangilanish yozmaydi.
        var recent = SecondsAgo(120);
        await SetLastUsedAtAsync(account.TenantId, recent);

        Assert.True((await RenewAsync(account.Token, name)).IsSuccess);
        Assert.Equal(recent, await LastUsedAtAsync(account.TenantId));

        // 6 daqiqa oldin — yangilanish endi yozadi.
        var stale = SecondsAgo(6 * 60);
        await SetLastUsedAtAsync(account.TenantId, stale);

        Assert.True((await RenewAsync(account.Token, name)).IsSuccess);
        var written = await LastUsedAtAsync(account.TenantId);
        Assert.NotNull(written);
        Assert.True(written > recent);

        // Hech qachon yozilmagan (null) — yangilanish yozadi.
        await SetLastUsedAtAsync(account.TenantId, null);

        Assert.True((await RenewAsync(account.Token, name)).IsSuccess);
        Assert.NotNull(await LastUsedAtAsync(account.TenantId));
    }

    [Fact]
    public async Task Renewal_denial_writes_nothing()
    {
        var name = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(name);

        var stale = SecondsAgo(6 * 60);
        await SetLastUsedAtAsync(account.TenantId, stale);

        Assert.False((await RenewAsync(account.Token, UniqueName())).IsSuccess);
        Assert.Equal(stale, await LastUsedAtAsync(account.TenantId));
    }

    [Fact]
    public async Task Open_still_writes_last_used()
    {
        var name = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(name);

        // Ochilish throttle qilinmaydi: 1 daqiqa oldingi qiymat ham yangilanadi.
        var recent = SecondsAgo(60);
        await SetLastUsedAtAsync(account.TenantId, recent);

        await using (var scope = fixture.CreateScope())
        {
            var reopened = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
                .HandleAsync(new AuthorizeTunnelCommand(account.Token, name, null, null, null));
            Assert.True(reopened.IsSuccess);
        }

        Assert.True(await LastUsedAtAsync(account.TenantId) > recent);
    }

    /// <summary>
    /// Eski edge (renewal maydonini bilmaydi) + yangi AP: bayroq yo'q —
    /// so'rov bugungidek oddiy ochilish: mavjud nom beriladi, yangisi band qilinadi.
    /// </summary>
    [Fact]
    public async Task Renewal_flag_absent_behaves_as_open()
    {
        var existing = UniqueName();
        var account = await CreateAccountWithOpenTunnelAsync(existing);

        await using var scope = fixture.CreateScope();
        var authorize = scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>();

        var command = new AuthorizeTunnelCommand(account.Token, existing, null, null, null);
        Assert.False(command.IsRenewal);

        var again = await authorize.HandleAsync(command);
        Assert.True(again.IsSuccess);
        Assert.Equal(existing, again.Value.Subdomain);

        // Free kvotasi 1 nom — yangi nomni sinash uchun Pro'ga o'tkazamiz.
        await ChangePlanAsync(scope, account.TenantId, "pro");

        var fresh = UniqueName();
        var reserved = await authorize.HandleAsync(new AuthorizeTunnelCommand(account.Token, fresh, null, null, null));
        Assert.True(reserved.IsSuccess);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(account.TenantId, (await db.Subdomains.SingleAsync(s => s.Name == fresh)).TenantId);
    }

    /// <summary>
    /// Edge lease'ni ko'pi bilan LeaseTtlSeconds/2 da yangilaydi (D-6). 60
    /// sekundlik SLO uchun yarim lease ≥ 30 (AP'ga ortiqcha yuk bermaslik)
    /// va ≤ 50 (RPC timeout bilan birga 60 dan oshmaslik) bo'lishi kerak.
    /// </summary>
    [Fact]
    public void Lease_ttl_is_60_and_renewal_budget_holds()
    {
        Assert.Equal(60, AuthorizeTunnelHandler.LeaseTtlSeconds);

        var halfLease = AuthorizeTunnelHandler.LeaseTtlSeconds / 2;
        Assert.InRange(halfLease, 30, 50);

        Assert.Equal(TimeSpan.FromMinutes(5), AuthorizeTunnelHandler.LastUsedRenewalWriteInterval);
    }

    private static async Task ChangePlanAsync(AsyncServiceScope scope, int tenantId, string plan)
    {
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var slug = await db.Tenants.Where(t => t.Id == tenantId).Select(t => t.Slug).SingleAsync();

        var changed = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(new ChangePlanCommand(slug, plan, null, "test", null, null));
        Assert.True(changed.IsSuccess);
    }
}
