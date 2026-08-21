using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Subdomains;

public sealed record ReleaseSubdomainCommand(int TenantId, int SubdomainId);

public sealed class ReleaseSubdomainHandler(IAccessDbContext db)
{
    public async Task<Result> HandleAsync(
        ReleaseSubdomainCommand command,
        CancellationToken cancellationToken = default)
    {
        var subdomain = await db.Subdomains.SingleOrDefaultAsync(
            s => s.Id == command.SubdomainId && s.TenantId == command.TenantId,
            cancellationToken);

        if (subdomain is null)
        {
            return SubdomainErrors.NotFound;
        }

        // Yozuv o'chirilmaydi, `Released` holatiga o'tadi: ARCHITECTURE.md
        // §3.1.3 dagi karantin g'oyasi — eski marshrutlar va DNS keshi
        // tozalanmaguncha nom qayta taqsimlanmasligi kerak.
        subdomain.Status = SubdomainStatus.Released;
        await db.SaveChangesAsync(cancellationToken);

        return Result.Success();
    }
}
