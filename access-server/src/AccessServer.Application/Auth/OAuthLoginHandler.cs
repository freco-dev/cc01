using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Domain.Entities;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Auth;

/// <param name="ProviderUserId">
/// Provayderdagi barqaror identifikator (`sub` / GitHub `id`). Email emas:
/// email o'zgarishi mumkin, `sub` esa yo'q.
/// </param>
public sealed record OAuthLoginCommand(
    OAuthProvider Provider,
    string ProviderUserId,
    string? Email,
    bool EmailVerified,
    string? FullName);

public sealed class OAuthLoginHandler(
    IAccessDbContext db,
    IAccessTokenIssuer tokenIssuer,
    TimeProvider timeProvider)
{
    public async Task<Result<LoginResult>> HandleAsync(
        OAuthLoginCommand command,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.ProviderUserId))
        {
            return OAuthErrors.SubjectMissing;
        }

        var now = timeProvider.GetUtcNow();
        var providerUserId = command.ProviderUserId.Trim();

        // 1) Provayder allaqachon bog'langanmi — eng oddiy yo'l.
        var linked = await FindByProviderIdAsync(command.Provider, providerUserId, cancellationToken);
        if (linked is not null)
        {
            return Authorize(linked);
        }

        // 2) Bog'lanmagan. Endi emailga tayanamiz — va aynan shu joyda
        //    hisobni egallab olish xavfi bor, shuning uchun provayder
        //    emailni TASDIQLAGAN bo'lishi shart.
        var email = command.Email?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(email))
        {
            return OAuthErrors.EmailMissing;
        }

        if (!command.EmailVerified)
        {
            return OAuthErrors.EmailUnverified;
        }

        var existing = await db.Users
            .Include(u => u.Tenant)
            .SingleOrDefaultAsync(u => u.Email == email, cancellationToken);

        if (existing is not null)
        {
            LinkProvider(existing, command.Provider, providerUserId);

            // Provayder emailni tasdiqlagan, demak bizda ham tasdiqlangan
            // hisoblanadi. Birinchi tasdiqlash vaqti saqlanadi.
            existing.EmailVerifiedAt ??= now;

            await db.SaveChangesAsync(cancellationToken);
            return Authorize(existing);
        }

        // 3) Yangi hisob. Parol yo'q — faqat OAuth orqali kiriladi.
        var fullName = string.IsNullOrWhiteSpace(command.FullName)
            ? email[..email.IndexOf('@', StringComparison.Ordinal)]
            : command.FullName.Trim();

        var tenant = new Tenant
        {
            Slug = TenantSlug.Generate(),
            Name = fullName,
            Plan = PlanCode.Free,
            Status = TenantStatus.Active,
        };

        var user = new User
        {
            Tenant = tenant,
            FullName = fullName,
            Email = email,
            PasswordHash = null,
            EmailVerifiedAt = now,
            Status = UserStatus.Active,
        };

        LinkProvider(user, command.Provider, providerUserId);

        db.Tenants.Add(tenant);
        db.Users.Add(user);

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // Tekshiruv bilan yozish orasida boshqa so'rov shu emailni
            // yozib ulgurgan. Qayta o'qib, bog'lab yuboramiz.
            var raced = await db.Users
                .Include(u => u.Tenant)
                .SingleOrDefaultAsync(u => u.Email == email, cancellationToken);

            if (raced is null)
            {
                throw;
            }

            LinkProvider(raced, command.Provider, providerUserId);
            raced.EmailVerifiedAt ??= now;
            await db.SaveChangesAsync(cancellationToken);
            return Authorize(raced);
        }

        return Authorize(user);
    }

    private Task<User?> FindByProviderIdAsync(
        OAuthProvider provider,
        string providerUserId,
        CancellationToken cancellationToken) =>
        provider switch
        {
            OAuthProvider.Github => db.Users.Include(u => u.Tenant)
                .SingleOrDefaultAsync(u => u.GithubId == providerUserId, cancellationToken),

            OAuthProvider.Google => db.Users.Include(u => u.Tenant)
                .SingleOrDefaultAsync(u => u.GoogleId == providerUserId, cancellationToken),

            _ => Task.FromResult<User?>(null),
        };

    private static void LinkProvider(User user, OAuthProvider provider, string providerUserId)
    {
        switch (provider)
        {
            case OAuthProvider.Github:
                user.GithubId = providerUserId;
                break;

            case OAuthProvider.Google:
                user.GoogleId = providerUserId;
                break;
        }
    }

    private Result<LoginResult> Authorize(User user)
    {
        if (user.Status != UserStatus.Active || user.Tenant.Status != TenantStatus.Active)
        {
            return AuthErrors.AccountSuspended;
        }

        var issued = tokenIssuer.Issue(user);

        return new LoginResult(
            issued.Token,
            issued.ExpiresAt,
            user.IsEmailVerified,
            user.Tenant.Slug);
    }
}
