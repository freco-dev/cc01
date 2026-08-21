using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Tokens;

public sealed record CreateApiTokenCommand(int UserId, string Name, DateTimeOffset? ExpiresAt);

/// <param name="Secret">
/// To'liq token. Faqat SHU javobda qaytariladi va boshqa hech qachon —
/// bazada faqat hash bor.
/// </param>
public sealed record CreateApiTokenResult(int TokenId, string Prefix, string Secret);

public sealed class CreateApiTokenHandler(
    IAccessDbContext db,
    IApiTokenFactory tokenFactory,
    TimeProvider timeProvider)
{
    public async Task<Result<CreateApiTokenResult>> HandleAsync(
        CreateApiTokenCommand command,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.Name))
        {
            return TokenErrors.NameRequired;
        }

        var user = await db.Users
            .SingleOrDefaultAsync(u => u.Id == command.UserId, cancellationToken);

        if (user is null)
        {
            return TokenErrors.NotFound;
        }

        // DEV_SPEC §6.5 A-S4: tasdiqlanmagan email bilan tunnel ochib
        // bo'lmaydi — demak token berishning ham ma'nosi yo'q.
        if (!user.IsEmailVerified)
        {
            return TokenErrors.EmailNotVerified;
        }

        var now = timeProvider.GetUtcNow();
        var generated = tokenFactory.Create();

        var token = new ApiToken
        {
            TenantId = user.TenantId,
            CreatedByUserId = user.Id,
            Prefix = generated.Prefix,
            TokenHash = generated.Hash,
            Name = command.Name.Trim(),
            ExpiresAt = command.ExpiresAt,
        };

        db.ApiTokens.Add(token);
        await db.SaveChangesAsync(cancellationToken);

        _ = now;
        return new CreateApiTokenResult(token.Id, token.Prefix, generated.Secret);
    }
}
