using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Application.Plans;
using AccessServer.Application.Validation;
using AccessServer.Domain.Entities;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Subdomains;

public sealed record ReserveSubdomainCommand(int TenantId, string Name);

public sealed record ReserveSubdomainResult(int Id, string Name, SubdomainStatus Status);

public sealed class ReserveSubdomainHandler(IAccessDbContext db, EffectivePlanResolver planResolver)
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

        var limits = (await planResolver.ResolveAsync(tenant.Id, cancellationToken)).Limits;

        var existing = await db.Subdomains
            .SingleOrDefaultAsync(s => s.Name == name, cancellationToken);

        if (existing is not null)
        {
            if (existing.TenantId != command.TenantId)
            {
                return SubdomainErrors.Taken;
            }

            // O'ziniki va band — idempotent muvaffaqiyat.
            if (existing.Status != SubdomainStatus.Released)
            {
                return new ReserveSubdomainResult(existing.Id, existing.Name, existing.Status);
            }

            // O'zi bo'shatgan nom — kvota ichida qaytarib olinadi (tunnel
            // ochilishi bilan bir xil qoida, qarang SubdomainQuota).
            if (!await db.Subdomains.TryReclaimAsync(existing, limits.MaxSubdomains, cancellationToken))
            {
                return SubdomainErrors.QuotaExceeded;
            }

            await db.SaveChangesAsync(cancellationToken);
            return new ReserveSubdomainResult(existing.Id, existing.Name, existing.Status);
        }

        var owned = await db.Subdomains.CountOwnedAsync(command.TenantId, cancellationToken);

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
