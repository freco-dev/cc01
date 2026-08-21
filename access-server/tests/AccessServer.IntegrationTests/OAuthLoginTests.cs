using AccessServer.Application.Auth;
using AccessServer.Domain.Enums;
using AccessServer.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AccessServer.IntegrationTests;

[Collection(PostgresCollection.Name)]
public sealed class OAuthLoginTests(PostgresFixture fixture)
{
    private const string Password = "correct horse battery staple";

    private static string UniqueEmail() => $"o{Guid.NewGuid():n}@example.com";

    private static string UniqueProviderId() => Guid.NewGuid().ToString("n");

    [Fact]
    public async Task First_login_creates_tenant_and_verified_user()
    {
        var email = UniqueEmail();
        var providerId = UniqueProviderId();
        await using var scope = fixture.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>()
            .HandleAsync(new OAuthLoginCommand(
                OAuthProvider.Github, providerId, email, EmailVerified: true, "Aziz Karimov"));

        Assert.True(result.IsSuccess);
        Assert.True(result.Value.EmailVerified);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var user = await db.Users.SingleAsync(u => u.Email == email);

        Assert.Equal(providerId, user.GithubId);
        Assert.Null(user.GoogleId);

        // OAuth orqali kirgan foydalanuvchida parol yo'q.
        Assert.Null(user.PasswordHash);
        Assert.NotNull(user.EmailVerifiedAt);
    }

    [Fact]
    public async Task Repeat_login_reuses_the_same_user()
    {
        var email = UniqueEmail();
        var providerId = UniqueProviderId();
        await using var scope = fixture.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>();

        var first = await handler.HandleAsync(new OAuthLoginCommand(
            OAuthProvider.Google, providerId, email, true, "A"));

        // Ikkinchi safar email O'ZGARGAN bo'lsa ham — `sub` bo'yicha topiladi.
        var second = await handler.HandleAsync(new OAuthLoginCommand(
            OAuthProvider.Google, providerId, "changed-" + email, true, "A"));

        Assert.True(second.IsSuccess);
        Assert.Equal(first.Value.TenantSlug, second.Value.TenantSlug);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Equal(1, await db.Users.CountAsync(u => u.GoogleId == providerId));
    }

    [Fact]
    public async Task Verified_email_links_to_existing_password_account()
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();

        var registered = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("Aziz", email, Password, false));

        var result = await scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>()
            .HandleAsync(new OAuthLoginCommand(
                OAuthProvider.Github, UniqueProviderId(), email, EmailVerified: true, "Aziz"));

        Assert.True(result.IsSuccess);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var user = await db.Users.SingleAsync(u => u.Id == registered.Value.UserId);

        Assert.NotNull(user.GithubId);

        // Mavjud parol saqlanadi — foydalanuvchi ikkala usulda kira oladi.
        Assert.NotNull(user.PasswordHash);

        // Provayder emailni tasdiqlagan, demak email endi tasdiqlangan.
        Assert.True(user.IsEmailVerified);
    }

    /// <summary>
    /// Hisobni egallab olishga qarshi asosiy himoya: tajovuzkor begona
    /// emailni o'z provayder hisobiga yozib qo'yishi mumkin. Provayder uni
    /// tasdiqlamagan bo'lsa, biz mavjud hisobga bog'lamaymiz.
    /// </summary>
    [Fact]
    public async Task Unverified_email_cannot_link_to_existing_account()
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();

        var registered = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("Egasi", email, Password, false));

        var result = await scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>()
            .HandleAsync(new OAuthLoginCommand(
                OAuthProvider.Github, UniqueProviderId(), email, EmailVerified: false, "Tajovuzkor"));

        Assert.Equal("OAUTH_EMAIL_UNVERIFIED", result.Error!.Code);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var user = await db.Users.SingleAsync(u => u.Id == registered.Value.UserId);

        // Hisobga hech narsa bog'lanmagan.
        Assert.Null(user.GithubId);
    }

    [Fact]
    public async Task Unverified_email_cannot_create_account_either()
    {
        await using var scope = fixture.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>()
            .HandleAsync(new OAuthLoginCommand(
                OAuthProvider.Google, UniqueProviderId(), UniqueEmail(), EmailVerified: false, "A"));

        Assert.Equal("OAUTH_EMAIL_UNVERIFIED", result.Error!.Code);
    }

    [Fact]
    public async Task Missing_email_is_rejected()
    {
        await using var scope = fixture.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>()
            .HandleAsync(new OAuthLoginCommand(
                OAuthProvider.Github, UniqueProviderId(), Email: null, EmailVerified: true, "A"));

        Assert.Equal("OAUTH_EMAIL_MISSING", result.Error!.Code);
    }

    [Fact]
    public async Task Missing_subject_is_rejected()
    {
        await using var scope = fixture.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>()
            .HandleAsync(new OAuthLoginCommand(
                OAuthProvider.Github, ProviderUserId: "  ", Email: UniqueEmail(),
                EmailVerified: true, FullName: "A"));

        Assert.Equal("OAUTH_SUBJECT_MISSING", result.Error!.Code);
    }

    [Fact]
    public async Task Two_providers_can_link_to_one_account()
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>();

        await handler.HandleAsync(new OAuthLoginCommand(
            OAuthProvider.Github, UniqueProviderId(), email, true, "A"));

        await handler.HandleAsync(new OAuthLoginCommand(
            OAuthProvider.Google, UniqueProviderId(), email, true, "A"));

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var user = await db.Users.SingleAsync(u => u.Email == email);

        Assert.NotNull(user.GithubId);
        Assert.NotNull(user.GoogleId);
    }

    [Fact]
    public async Task Suspended_tenant_cannot_log_in()
    {
        var email = UniqueEmail();
        var providerId = UniqueProviderId();
        await using var scope = fixture.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>();

        await handler.HandleAsync(new OAuthLoginCommand(
            OAuthProvider.Github, providerId, email, true, "A"));

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var user = await db.Users.Include(u => u.Tenant).SingleAsync(u => u.Email == email);
        user.Tenant.Status = TenantStatus.Suspended;
        await db.SaveChangesAsync();

        var result = await handler.HandleAsync(new OAuthLoginCommand(
            OAuthProvider.Github, providerId, email, true, "A"));

        Assert.Equal("ACCOUNT_SUSPENDED", result.Error!.Code);
    }

    [Fact]
    public async Task Full_name_falls_back_to_email_local_part()
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();

        await scope.ServiceProvider.GetRequiredService<OAuthLoginHandler>()
            .HandleAsync(new OAuthLoginCommand(
                OAuthProvider.Github, UniqueProviderId(), email, true, FullName: null));

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var user = await db.Users.SingleAsync(u => u.Email == email);

        Assert.Equal(email[..email.IndexOf('@', StringComparison.Ordinal)], user.FullName);
    }
}
