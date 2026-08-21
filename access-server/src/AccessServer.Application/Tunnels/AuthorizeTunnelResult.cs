using AccessServer.Application.Subdomains;
using AccessServer.Domain.Enums;

namespace AccessServer.Application.Tunnels;

/// <summary>
/// Rad etish sabablari. Nomlar proto/cc01/v1/access.proto dagi
/// `DenialCode` bilan bir xil — API qatlami ularni to'g'ridan-to'g'ri
/// xaritalaydi.
/// </summary>
public enum TunnelDenial
{
    None = 0,
    TokenInvalid,
    TokenRevoked,
    TokenExpired,
    EmailNotVerified,
    SubdomainInvalid,
    SubdomainNotOwned,
    SubdomainBusy,
    DomainNotVerified,
    QuotaTunnelsExceeded,
    PlanSuspended,
}

public sealed record AuthorizeTunnelGrant(
    int UserId,
    string TenantSlug,
    PlanCode Plan,
    string Subdomain,
    PlanLimits Limits,
    int LeaseTtlSeconds);
