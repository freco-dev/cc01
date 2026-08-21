using AccessServer.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Tokens;

/// <summary>Sir hech qachon qaytarilmaydi — faqat prefiks.</summary>
public sealed record ApiTokenSummary(
    int Id,
    string Prefix,
    string Name,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RevokedAt,
    bool IsActive);

public sealed class ListApiTokensHandler(IAccessDbContext db, TimeProvider timeProvider)
{
    public async Task<IReadOnlyList<ApiTokenSummary>> HandleAsync(
        int tenantId,
        CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        return await db.ApiTokens
            .Where(t => t.TenantId == tenantId)
            .OrderByDescending(t => t.CreatedAt)
            .Select(t => new ApiTokenSummary(
                t.Id,
                t.Prefix,
                t.Name,
                t.CreatedAt,
                t.LastUsedAt,
                t.ExpiresAt,
                t.RevokedAt,
                t.RevokedAt == null && (t.ExpiresAt == null || t.ExpiresAt > now)))
            .ToListAsync(cancellationToken);
    }
}
