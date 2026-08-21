using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Abstractions;

/// <summary>
/// Application qatlami baza bilan shu interfeys orqali ishlaydi.
/// Implementatsiya Infrastructure'da (AccessDbContext) — bog'liqlik
/// yo'nalishi ichkariga qaragan bo'lib qoladi.
/// </summary>
public interface IAccessDbContext
{
    DbSet<Tenant> Tenants { get; }

    DbSet<User> Users { get; }

    DbSet<ApiToken> ApiTokens { get; }

    DbSet<Subdomain> Subdomains { get; }

    DbSet<UserVerificationToken> UserVerificationTokens { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
