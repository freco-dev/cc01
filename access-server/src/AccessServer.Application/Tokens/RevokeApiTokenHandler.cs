using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Tokens;

public sealed record RevokeApiTokenCommand(int TenantId, int TokenId);

public sealed class RevokeApiTokenHandler(IAccessDbContext db, TimeProvider timeProvider)
{
    public async Task<Result> HandleAsync(
        RevokeApiTokenCommand command,
        CancellationToken cancellationToken = default)
    {
        // TenantId filtri majburiy: aks holda ID'ni bilgan boshqa tenant
        // begona tokenni bekor qila oladi.
        var token = await db.ApiTokens.SingleOrDefaultAsync(
            t => t.Id == command.TokenId && t.TenantId == command.TenantId,
            cancellationToken);

        if (token is null)
        {
            return TokenErrors.NotFound;
        }

        // Idempotent: qayta bekor qilish xato emas, birinchi vaqt saqlanadi.
        if (token.RevokedAt is null)
        {
            token.RevokedAt = timeProvider.GetUtcNow();
            await db.SaveChangesAsync(cancellationToken);
        }

        return Result.Success();
    }
}
