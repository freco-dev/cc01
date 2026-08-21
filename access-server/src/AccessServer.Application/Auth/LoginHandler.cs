using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Auth;

public sealed record LoginCommand(string Email, string Password);

public sealed record LoginResult(
    string AccessToken,
    DateTimeOffset ExpiresAt,
    bool EmailVerified,
    string TenantSlug);

public sealed class LoginHandler(
    IAccessDbContext db,
    IPasswordHasher passwordHasher,
    IAccessTokenIssuer tokenIssuer)
{
    public async Task<Result<LoginResult>> HandleAsync(
        LoginCommand command,
        CancellationToken cancellationToken = default)
    {
        var email = command.Email?.Trim().ToLowerInvariant() ?? string.Empty;

        var user = await db.Users
            .Include(u => u.Tenant)
            .SingleOrDefaultAsync(u => u.Email == email, cancellationToken);

        // Foydalanuvchi topilmasa ham hash hisoblaymiz: aks holda javob vaqti
        // mavjud va mavjud bo'lmagan email uchun farq qiladi va bu hisob
        // borligini oshkor qiladi (timing orqali user enumeration).
        var storedHash = user?.PasswordHash ?? passwordHasher.DummyHash;
        var passwordMatches = passwordHasher.Verify(command.Password ?? string.Empty, storedHash, out var needsRehash);

        if (user is null || user.PasswordHash is null || !passwordMatches)
        {
            return AuthErrors.InvalidCredentials;
        }

        if (user.Status != UserStatus.Active || user.Tenant.Status != TenantStatus.Active)
        {
            return AuthErrors.AccountSuspended;
        }

        if (needsRehash)
        {
            user.PasswordHash = passwordHasher.Hash(command.Password!);
            await db.SaveChangesAsync(cancellationToken);
        }

        var issued = tokenIssuer.Issue(user);

        return new LoginResult(
            issued.Token,
            issued.ExpiresAt,
            user.IsEmailVerified,
            user.Tenant.Slug);
    }
}
