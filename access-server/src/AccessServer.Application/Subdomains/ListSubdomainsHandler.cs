using AccessServer.Application.Abstractions;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Subdomains;

public sealed record SubdomainSummary(
    int Id,
    string Name,
    SubdomainStatus Status,
    DateTimeOffset? ReservedUntil,
    DateTimeOffset CreatedAt);

public sealed class ListSubdomainsHandler(IAccessDbContext db)
{
    public async Task<IReadOnlyList<SubdomainSummary>> HandleAsync(
        int tenantId,
        CancellationToken cancellationToken = default) =>
        await db.Subdomains
            .Where(s => s.TenantId == tenantId)
            .OrderBy(s => s.Name)
            .Select(s => new SubdomainSummary(
                s.Id, s.Name, s.Status, s.ReservedUntil, s.CreatedAt))
            .ToListAsync(cancellationToken);
}
