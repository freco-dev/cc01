using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Application.Validation;
using AccessServer.Domain.Entities;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Subdomains;

public sealed record ReserveSubdomainCommand(int TenantId, string Name);

public sealed record ReserveSubdomainResult(int Id, string Name, SubdomainStatus Status);

public sealed class ReserveSubdomainHandler(IAccessDbContext db)
{
    public async Task<Result<ReserveSubdomainResult>> HandleAsync(
        ReserveSubdomainCommand command,
        CancellationToken cancellationToken = default)
    {
        // Nomni normallashtirish: "MyApp" → "myapp". Validatsiya normallashgan
        // qiymat ustida ishlaydi, aks holda katta harf har doim rad etilardi.
        var name = command.Name?.Trim().ToLowerInvariant() ?? string.Empty;

        var validation = SubdomainRules.Validate(name);
        if (validation != SubdomainValidation.Ok)
        {
            return SubdomainErrors.ForValidation(validation);
        }

        var tenant = await db.Tenants
            .SingleOrDefaultAsync(t => t.Id == command.TenantId, cancellationToken);

        if (tenant is null)
        {
            return SubdomainErrors.NotFound;
        }

        var existing = await db.Subdomains
            .SingleOrDefaultAsync(s => s.Name == name, cancellationToken);

        if (existing is not null)
        {
            // O'ziniki bo'lsa — idempotent muvaffaqiyat, begona bo'lsa — konflikt.
            return existing.TenantId == command.TenantId
                ? new ReserveSubdomainResult(existing.Id, existing.Name, existing.Status)
                : SubdomainErrors.Taken;
        }

        var limits = PlanCatalog.For(tenant.Plan);
        var owned = await db.Subdomains
            .CountAsync(s => s.TenantId == command.TenantId
                             && s.Status != SubdomainStatus.Released, cancellationToken);

        if (owned >= limits.MaxSubdomains)
        {
            return SubdomainErrors.QuotaExceeded;
        }

        var subdomain = new Subdomain
        {
            TenantId = command.TenantId,
            Name = name,
            Status = SubdomainStatus.Reserved,
        };

        db.Subdomains.Add(subdomain);

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // Tekshiruv bilan yozish orasidagi poyga — unique indeks ushlaydi.
            return SubdomainErrors.Taken;
        }

        return new ReserveSubdomainResult(subdomain.Id, subdomain.Name, subdomain.Status);
    }
}
