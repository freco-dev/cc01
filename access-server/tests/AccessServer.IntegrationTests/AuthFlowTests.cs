using AccessServer.Application.Auth;
using AccessServer.Application.Tokens;
using AccessServer.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AccessServer.IntegrationTests;

[Collection(PostgresCollection.Name)]
public sealed class AuthFlowTests(PostgresFixture fixture)
{
    private static string UniqueEmail() => $"u{Guid.NewGuid():n}@example.com";

    private const string GoodPassword = "correct horse battery staple";

    [Fact]
    public async Task Register_creates_tenant_and_unverified_user()
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("Aziz Karimov", email, GoodPassword, true));

        Assert.True(result.IsSuccess);
        Assert.StartsWith("t_", result.Value.TenantSlug, StringComparison.Ordinal);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var user = await db.Users.Include(u => u.Tenant).SingleAsync(u => u.Email == email);

        Assert.False(user.IsEmailVerified);
        Assert.Equal(result.Value.TenantSlug, user.Tenant.Slug);

        // Parol ochiq saqlanmasligi kerak (DEV_SPEC §6.5 A-S1).
        Assert.NotNull(user.PasswordHash);
        Assert.DoesNotContain(GoodPassword, user.PasswordHash, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Register_normalizes_email_case()
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RegisterUserHandler>();

        await handler.HandleAsync(new RegisterUserCommand("A", email.ToUpperInvariant(), GoodPassword, false));

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.True(await db.Users.AnyAsync(u => u.Email == email.ToLowerInvariant()));
    }

    [Fact]
    public async Task Register_rejects_duplicate_email()
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();
        var handler = scope.ServiceProvider.GetRequiredService<RegisterUserHandler>();

        await handler.HandleAsync(new RegisterUserCommand("A", email, GoodPassword, false));
        var second = await handler.HandleAsync(new RegisterUserCommand("B", email, GoodPassword, false));

        Assert.False(second.IsSuccess);
        Assert.Equal("EMAIL_TAKEN", second.Error!.Code);
    }

    [Theory]
    [InlineData("short", "PASSWORD_TOO_SHORT")]
    [InlineData("elevenchars", "PASSWORD_TOO_SHORT")]
    public async Task Register_enforces_password_length(string password, string expectedCode)
    {
        await using var scope = fixture.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("A", UniqueEmail(), password, false));

        Assert.Equal(expectedCode, result.Error!.Code);
    }

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("missing@")]
    [InlineData("")]
    public async Task Register_rejects_invalid_email(string email)
    {
        await using var scope = fixture.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("A", email, GoodPassword, false));

        Assert.Equal("EMAIL_INVALID", result.Error!.Code);
    }

    [Fact]
    public async Task Verify_email_marks_user_and_token_is_single_use()
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();

        await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("A", email, GoodPassword, false));

        var token = fixture.Emails.TokenFor(email);
        var verify = scope.ServiceProvider.GetRequiredService<VerifyEmailHandler>();

        Assert.True((await verify.HandleAsync(new VerifyEmailCommand(token))).IsSuccess);

        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.True((await db.Users.SingleAsync(u => u.Email == email)).IsEmailVerified);

        // Ikkinchi marta ishlatib bo'lmaydi.
        var replay = await verify.HandleAsync(new VerifyEmailCommand(token));
        Assert.Equal("VERIFICATION_TOKEN_INVALID", replay.Error!.Code);
    }

    [Fact]
    public async Task Verify_email_rejects_unknown_token()
    {
        await using var scope = fixture.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<VerifyEmailHandler>()
            .HandleAsync(new VerifyEmailCommand("deadbeef"));

        Assert.Equal("VERIFICATION_TOKEN_INVALID", result.Error!.Code);
    }

    [Fact]
    public async Task Login_succeeds_and_returns_token()
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();

        await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("A", email, GoodPassword, false));

        var result = await scope.ServiceProvider.GetRequiredService<LoginHandler>()
            .HandleAsync(new LoginCommand(email, GoodPassword));

        Assert.True(result.IsSuccess);
        Assert.False(string.IsNullOrWhiteSpace(result.Value.AccessToken));
        Assert.False(result.Value.EmailVerified);
        Assert.Equal(3, result.Value.AccessToken.Split('.').Length);   // JWT
    }

    [Theory]
    [InlineData(true)]   // mavjud foydalanuvchi, noto'g'ri parol
    [InlineData(false)]  // umuman mavjud bo'lmagan email
    public async Task Login_failure_uses_same_error_code(bool userExists)
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();

        if (userExists)
        {
            await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
                .HandleAsync(new RegisterUserCommand("A", email, GoodPassword, false));
        }

        var result = await scope.ServiceProvider.GetRequiredService<LoginHandler>()
            .HandleAsync(new LoginCommand(email, "definitely wrong password"));

        // Ikkala holatda bir xil xato — hisob mavjudligi oshkor bo'lmaydi.
        Assert.Equal("INVALID_CREDENTIALS", result.Error!.Code);
    }

    [Fact]
    public async Task Token_creation_requires_verified_email()
    {
        var email = UniqueEmail();
        await using var scope = fixture.CreateScope();

        var registered = await scope.ServiceProvider.GetRequiredService<RegisterUserHandler>()
            .HandleAsync(new RegisterUserCommand("A", email, GoodPassword, false));

        var result = await scope.ServiceProvider.GetRequiredService<CreateApiTokenHandler>()
            .HandleAsync(new CreateApiTokenCommand(registered.Value.UserId, "laptop", null));

        Assert.Equal("EMAIL_NOT_VERIFIED", result.Error!.Code);
    }
}
