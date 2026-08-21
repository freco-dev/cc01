using AccessServer.Application.Auth;
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

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var tenant = await db.Tenants.SingleAsync(t => t.Id == account.TenantId);
        tenant.Plan = PlanCode.Pro;
        await db.SaveChangesAsync();

        var result = await scope.ServiceProvider.GetRequiredService<AuthorizeTunnelHandler>()
            .HandleAsync(new AuthorizeTunnelCommand(account.Token, UniqueName(), null, null, null));

        Assert.True(result.IsSuccess);
        Assert.Equal(128, result.Value.Limits.MaxConnectionsPerTunnel);
        Assert.Equal(PlanCode.Pro, result.Value.Plan);
    }
}
