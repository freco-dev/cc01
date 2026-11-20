using AccessServer.Application.Auth;
using AccessServer.Application.Subdomains;
using AccessServer.Application.Tokens;
using AccessServer.Application.Plans;
using AccessServer.Domain.Enums;
using AccessServer.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AccessServer.IntegrationTests;

[Collection(PostgresCollection.Name)]
public sealed class TokenAndSubdomainTests(PostgresFixture fixture)
{
    private const string GoodPassword = "correct horse battery staple";

    /// <summary>Ro'yxatdan o'tgan va emaili tasdiqlangan foydalanuvchi.</summary>
    private async Task<(int UserId, int TenantId)> CreateVerifiedUserAsync(AsyncServiceScope scope)
    {
        var email = $"u{Guid.NewGuid():n}@example.com";

        var registered = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("A", email, GoodPassword, false));

        await scope.ServiceProvider.GetRequiredService<VerifyEmailHandler>()
            .HandleAsync(new VerifyEmailCommand(fixture.Emails.TokenFor(email)));

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var user = await db.Users.SingleAsync(u => u.Id == registered.Value.UserId);

        return (user.Id, user.TenantId);
    }

    [Fact]
    public async Task Created_token_is_stored_only_as_hash()
    {
        await using var scope = fixture.CreateScope();
        var (userId, tenantId) = await CreateVerifiedUserAsync(scope);

        var result = await scope.ServiceProvider.GetRequiredService<CreateApiTokenHandler>()
            .HandleAsync(new CreateApiTokenCommand(userId, "laptop", null));

        Assert.True(result.IsSuccess);
        Assert.StartsWith(result.Value.Prefix, result.Value.Secret, StringComparison.Ordinal);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var stored = await db.ApiTokens.SingleAsync(t => t.Id == result.Value.TokenId);

        Assert.Equal(tenantId, stored.TenantId);
        Assert.Equal(32, stored.TokenHash.Length);   // SHA-256

        // Sirning o'zi bazaning hech bir matn maydonida bo'lmasligi kerak.
        Assert.NotEqual(result.Value.Secret, stored.Prefix);
        Assert.DoesNotContain(result.Value.Secret, stored.Name, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Revoked_token_becomes_inactive_immediately()
    {
        await using var scope = fixture.CreateScope();
        var (userId, tenantId) = await CreateVerifiedUserAsync(scope);

        var created = await scope.ServiceProvider.GetRequiredService<CreateApiTokenHandler>()
            .HandleAsync(new CreateApiTokenCommand(userId, "ci", null));

        var revoke = scope.ServiceProvider.GetRequiredService<RevokeApiTokenHandler>();
        Assert.True((await revoke.HandleAsync(new RevokeApiTokenCommand(tenantId, created.Value.TokenId))).IsSuccess);

        var listed = await scope.ServiceProvider.GetRequiredService<ListApiTokensHandler>()
            .HandleAsync(tenantId);

        Assert.False(listed.Single(t => t.Id == created.Value.TokenId).IsActive);

        // Idempotent: qayta bekor qilish xato emas.
        Assert.True((await revoke.HandleAsync(new RevokeApiTokenCommand(tenantId, created.Value.TokenId))).IsSuccess);
    }

    [Fact]
    public async Task Token_cannot_be_revoked_by_another_tenant()
    {
        await using var scope = fixture.CreateScope();
        var (ownerUserId, _) = await CreateVerifiedUserAsync(scope);
        var (_, otherTenantId) = await CreateVerifiedUserAsync(scope);

        var created = await scope.ServiceProvider.GetRequiredService<CreateApiTokenHandler>()
            .HandleAsync(new CreateApiTokenCommand(ownerUserId, "laptop", null));

        var result = await scope.ServiceProvider.GetRequiredService<RevokeApiTokenHandler>()
            .HandleAsync(new RevokeApiTokenCommand(otherTenantId, created.Value.TokenId));

        Assert.Equal("TOKEN_NOT_FOUND", result.Error!.Code);
    }

    [Fact]
    public async Task Subdomain_is_owned_after_reservation()
    {
        await using var scope = fixture.CreateScope();
        var (_, tenantId) = await CreateVerifiedUserAsync(scope);
        var name = "app" + Guid.NewGuid().ToString("n")[..10];

        var reserve = scope.ServiceProvider.GetRequiredService<ReserveSubdomainHandler>();
        var result = await reserve.HandleAsync(new ReserveSubdomainCommand(tenantId, name));

        Assert.True(result.IsSuccess);
        Assert.Equal(name, result.Value.Name);

        // O'zi qayta so'rasa — idempotent muvaffaqiyat, konflikt emas.
        var again = await reserve.HandleAsync(new ReserveSubdomainCommand(tenantId, name));
        Assert.True(again.IsSuccess);
        Assert.Equal(result.Value.Id, again.Value.Id);
    }

    [Fact]
    public async Task Subdomain_owned_by_another_tenant_is_rejected()
    {
        await using var scope = fixture.CreateScope();
        var (_, firstTenant) = await CreateVerifiedUserAsync(scope);
        var (_, secondTenant) = await CreateVerifiedUserAsync(scope);
        var name = "app" + Guid.NewGuid().ToString("n")[..10];

        var reserve = scope.ServiceProvider.GetRequiredService<ReserveSubdomainHandler>();
        await reserve.HandleAsync(new ReserveSubdomainCommand(firstTenant, name));

        var result = await reserve.HandleAsync(new ReserveSubdomainCommand(secondTenant, name));

        Assert.Equal("SUBDOMAIN_TAKEN", result.Error!.Code);
    }

    [Fact]
    public async Task Subdomain_name_is_normalized_to_lowercase()
    {
        await using var scope = fixture.CreateScope();
        var (_, tenantId) = await CreateVerifiedUserAsync(scope);
        var name = "App" + Guid.NewGuid().ToString("n")[..10].ToUpperInvariant();

        var result = await scope.ServiceProvider.GetRequiredService<ReserveSubdomainHandler>()
            .HandleAsync(new ReserveSubdomainCommand(tenantId, name));

        Assert.True(result.IsSuccess);
        Assert.Equal(name.ToLowerInvariant(), result.Value.Name);
    }

    [Theory]
    [InlineData("ab", "SUBDOMAIN_BAD_LENGTH")]
    [InlineData("-bad", "SUBDOMAIN_BAD_FORMAT")]
    [InlineData("bad-", "SUBDOMAIN_BAD_FORMAT")]
    [InlineData("a--b", "SUBDOMAIN_BAD_FORMAT")]
    [InlineData("www", "SUBDOMAIN_RESERVED")]
    [InlineData("", "SUBDOMAIN_EMPTY")]
    public async Task Invalid_subdomain_is_rejected(string name, string expectedCode)
    {
        await using var scope = fixture.CreateScope();
        var (_, tenantId) = await CreateVerifiedUserAsync(scope);

        var result = await scope.ServiceProvider.GetRequiredService<ReserveSubdomainHandler>()
            .HandleAsync(new ReserveSubdomainCommand(tenantId, name));

        Assert.Equal(expectedCode, result.Error!.Code);
    }

    [Fact]
    public async Task Free_plan_allows_only_one_subdomain()
    {
        await using var scope = fixture.CreateScope();
        var (_, tenantId) = await CreateVerifiedUserAsync(scope);
        var reserve = scope.ServiceProvider.GetRequiredService<ReserveSubdomainHandler>();

        var first = await reserve.HandleAsync(new ReserveSubdomainCommand(
            tenantId, "app" + Guid.NewGuid().ToString("n")[..10]));
        Assert.True(first.IsSuccess);

        var second = await reserve.HandleAsync(new ReserveSubdomainCommand(
            tenantId, "app" + Guid.NewGuid().ToString("n")[..10]));

        Assert.Equal("SUBDOMAIN_QUOTA_EXCEEDED", second.Error!.Code);
    }

    [Fact]
    public async Task Pro_plan_allows_more_subdomains()
    {
        await using var scope = fixture.CreateScope();
        var (_, tenantId) = await CreateVerifiedUserAsync(scope);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var slug = await db.Tenants.Where(t => t.Id == tenantId).Select(t => t.Slug).SingleAsync();
        var changed = await scope.ServiceProvider.GetRequiredService<ChangePlanHandler>()
            .HandleAsync(new ChangePlanCommand(slug, "pro", null, "test", null, null));
        Assert.True(changed.IsSuccess);

        var reserve = scope.ServiceProvider.GetRequiredService<ReserveSubdomainHandler>();

        for (var i = 0; i < 3; i++)
        {
            var result = await reserve.HandleAsync(new ReserveSubdomainCommand(
                tenantId, "app" + Guid.NewGuid().ToString("n")[..10]));
            Assert.True(result.IsSuccess);
        }
    }

    [Fact]
    public async Task Released_subdomain_frees_quota_but_keeps_record()
    {
        await using var scope = fixture.CreateScope();
        var (_, tenantId) = await CreateVerifiedUserAsync(scope);
        var reserve = scope.ServiceProvider.GetRequiredService<ReserveSubdomainHandler>();

        var first = await reserve.HandleAsync(new ReserveSubdomainCommand(
            tenantId, "app" + Guid.NewGuid().ToString("n")[..10]));

        await scope.ServiceProvider.GetRequiredService<ReleaseSubdomainHandler>()
            .HandleAsync(new ReleaseSubdomainCommand(tenantId, first.Value.Id));

        // Yozuv o'chirilmaydi — karantin uchun saqlanadi.
        var listed = await scope.ServiceProvider.GetRequiredService<ListSubdomainsHandler>()
            .HandleAsync(tenantId);
        Assert.Contains(listed, s => s.Id == first.Value.Id);

        // Kvota bo'shadi.
        var second = await reserve.HandleAsync(new ReserveSubdomainCommand(
            tenantId, "app" + Guid.NewGuid().ToString("n")[..10]));
        Assert.True(second.IsSuccess);
    }

    [Fact]
    public async Task Reserving_own_released_name_reclaims_it()
    {
        await using var scope = fixture.CreateScope();
        var (_, tenantId) = await CreateVerifiedUserAsync(scope);
        var reserve = scope.ServiceProvider.GetRequiredService<ReserveSubdomainHandler>();
        var name = "app" + Guid.NewGuid().ToString("n")[..10];

        var first = await reserve.HandleAsync(new ReserveSubdomainCommand(tenantId, name));
        await scope.ServiceProvider.GetRequiredService<ReleaseSubdomainHandler>()
            .HandleAsync(new ReleaseSubdomainCommand(tenantId, first.Value.Id));

        // Avval bu "idempotent muvaffaqiyat" qaytarib, qatorni `Released`
        // holida qoldirardi — nomni hech qachon qaytarib bo'lmasdi.
        var again = await reserve.HandleAsync(new ReserveSubdomainCommand(tenantId, name));

        Assert.True(again.IsSuccess);
        Assert.Equal(first.Value.Id, again.Value.Id);
        Assert.Equal(SubdomainStatus.Reserved, again.Value.Status);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(SubdomainStatus.Reserved,
            await db.Subdomains.AsNoTracking().Where(s => s.Id == first.Value.Id).Select(s => s.Status).SingleAsync());
    }

    [Fact]
    public async Task Reserving_own_released_name_counts_quota()
    {
        await using var scope = fixture.CreateScope();
        var (_, tenantId) = await CreateVerifiedUserAsync(scope);
        var reserve = scope.ServiceProvider.GetRequiredService<ReserveSubdomainHandler>();
        var name = "app" + Guid.NewGuid().ToString("n")[..10];

        var first = await reserve.HandleAsync(new ReserveSubdomainCommand(tenantId, name));
        await scope.ServiceProvider.GetRequiredService<ReleaseSubdomainHandler>()
            .HandleAsync(new ReleaseSubdomainCommand(tenantId, first.Value.Id));
        Assert.True((await reserve.HandleAsync(new ReserveSubdomainCommand(
            tenantId, "app" + Guid.NewGuid().ToString("n")[..10]))).IsSuccess);

        // Free: 1 nom, u allaqachon band.
        var again = await reserve.HandleAsync(new ReserveSubdomainCommand(tenantId, name));

        Assert.Equal(SubdomainErrors.QuotaExceeded.Code, again.Error!.Code);
    }
}
