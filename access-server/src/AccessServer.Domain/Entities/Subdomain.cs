using AccessServer.Domain.Enums;

namespace AccessServer.Domain.Entities;

/// <summary>
/// Tenantga biriktirilgan public subdomain. Egalik shu yerda hal qilinadi —
/// edge server "birinchi kelgan oladi" mantiqidan voz kechadi.
/// </summary>
public sealed class Subdomain : Entity
{
    public int TenantId { get; set; }

    public Tenant Tenant { get; set; } = null!;

    /// <summary>
    /// Kichik harfda, global unikal. Format qoidalari yagona manbadan:
    /// proto/cc01/v1/tunnel.proto, TunnelRequested.subdomain.
    /// </summary>
    public required string Name { get; set; }

    public SubdomainStatus Status { get; set; } = SubdomainStatus.Reserved;

    /// <summary>
    /// Free tarifda rezervatsiya muddatli bo'lishi mumkin (squatting'ga qarshi).
    /// null = muddatsiz.
    /// </summary>
    public DateTimeOffset? ReservedUntil { get; set; }
}
