using AccessServer.Domain.Entities;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Subdomains;

/// <summary>
/// Subdomain kvotasi va bo'shatilgan nomni qaytarib olish qoidasi — dashboard
/// (<see cref="ReserveSubdomainHandler"/>) va tunnel ochilishi
/// (AuthorizeTunnelHandler) uchun YAGONA joy. Ikkalasi turlicha ishlasa,
/// ochilish nomni beradi, lease yangilanishi esa uni rad etib tunnelni yopadi.
/// </summary>
internal static class SubdomainQuota
{
    /// <summary>Kvotaga sanaladigan nomlar: `Released` dan boshqa hammasi.</summary>
    public static Task<int> CountOwnedAsync(
        this DbSet<Subdomain> subdomains,
        int tenantId,
        CancellationToken cancellationToken) =>
        subdomains.CountAsync(
            s => s.TenantId == tenantId && s.Status != SubdomainStatus.Released,
            cancellationToken);

    /// <summary>
    /// Tenant o'zi bo'shatgan (`Released`) nomini qayta oladi: kvota ichida
    /// bo'lsa qator `Reserved` ga qaytadi. Karantin (ARCHITECTURE.md §3.1.3)
    /// nomni BOSHQA tenantga berishdan himoya qiladi — egasining o'ziga
    /// qaytishida eski marshrut yoki DNS keshi chalkashligi yo'q, chunki ular
    /// baribir shu tenantga olib boradi. Kvota esa yangi nomdagidek sanaladi:
    /// aks holda bo'shatish + qayta ochish limitni chetlab o'tardi.
    ///
    /// Chaqiruvchi SaveChanges'ni o'zi bajaradi. false — kvota to'lgan.
    /// </summary>
    public static async Task<bool> TryReclaimAsync(
        this DbSet<Subdomain> subdomains,
        Subdomain released,
        int maxSubdomains,
        CancellationToken cancellationToken)
    {
        if (await subdomains.CountOwnedAsync(released.TenantId, cancellationToken) >= maxSubdomains)
        {
            return false;
        }

        released.Status = SubdomainStatus.Reserved;
        return true;
    }
}
