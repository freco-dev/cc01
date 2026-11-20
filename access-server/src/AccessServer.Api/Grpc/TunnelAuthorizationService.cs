using AccessServer.Application.Plans;
using AccessServer.Application.Tunnels;
using Cc01.V1;
using Grpc.Core;

namespace AccessServer.Api.Grpc;

/// <summary>
/// AP ↔ Edge ichki kontrakti (proto/cc01/v1/access.proto).
///
/// Bu servis FAQAT ichki portda ochiladi (Program.cs dagi RequireInternalListener) —
/// internetdan erishib bo'lmaydi. DEV_SPEC §6.4.
/// </summary>
public sealed class TunnelAuthorizationService(
    AuthorizeTunnelHandler authorize,
    ILogger<TunnelAuthorizationService> logger)
    : AccessInternalService.AccessInternalServiceBase
{
    public override async Task<AuthorizeTunnelResponse> AuthorizeTunnel(
        AuthorizeTunnelRequest request,
        ServerCallContext context)
    {
        var result = await authorize.HandleAsync(
            new AuthorizeTunnelCommand(
                request.Token,
                request.Subdomain,
                request.CustomDomain,
                request.CliVersion,
                request.ClientIp,
                request.Renewal),
            context.CancellationToken);

        if (!result.IsSuccess)
        {
            var denial = ToDenialCode(result.Error!.Code);

            // To'liq token HECH QACHON log'ga yozilmaydi (§6.3). Yangilanish
            // rad etilsa edge ochiq tunnelni yopishi mumkin — shuning uchun
            // renewal belgisi log'da ko'rinadi.
            logger.LogInformation(
                "Tunnel rad etildi: {Denial} (subdomain={Subdomain}, ip={ClientIp}, renewal={Renewal})",
                denial, request.Subdomain, request.ClientIp, request.Renewal);

            return new AuthorizeTunnelResponse
            {
                Denial = new Denial
                {
                    Code = denial,
                    Message = result.Error.Message,
                },
            };
        }

        var grant = result.Value;

        if (request.Renewal)
        {
            // Har ochiq tunnel uchun ≤30 sekundda bir — Information'da shovqin bo'lardi.
            logger.LogDebug(
                "Lease yangilandi: {Subdomain} (tenant={Tenant}, plan={Plan}, renewal=true)",
                grant.Subdomain, grant.TenantSlug, grant.Plan);
        }

        return new AuthorizeTunnelResponse
        {
            Grant = new Grant
            {
                UserId = grant.UserId,
                TenantId = grant.TenantSlug,
                Plan = PlanCodeParser.ToWire(grant.Plan),
                Subdomain = grant.Subdomain,
                LeaseTtlS = (uint)grant.LeaseTtlSeconds,
                Limits = new Limits
                {
                    MaxTunnels = (uint)grant.Limits.MaxTunnels,
                    MaxConnsPerTunnel = (uint)grant.Limits.MaxConnectionsPerTunnel,
                    BandwidthBps = (ulong)grant.Limits.BandwidthBps,
                },
            },
        };
    }

    public override Task<ReportUsageResponse> ReportUsage(
        ReportUsageRequest request,
        ServerCallContext context)
    {
        // Faza 1: UsageRecord entity'si va billing hisob-kitobi (§8).
        // Hozircha qabul qilinganini tasdiqlaymiz, aks holda edge navbatni
        // cheksiz to'plab boradi.
        logger.LogDebug("Usage hisoboti: {Count} oyna (hali saqlanmaydi)", request.Windows.Count);

        return Task.FromResult(new ReportUsageResponse
        {
            Accepted = (uint)request.Windows.Count,
        });
    }

    /// <summary>
    /// `TunnelDenial` enum nomlarini proto'dagi `DenialCode` ga xaritalaydi.
    /// Ikkalasi bir xil nomlanadi, shuning uchun parse yetarli.
    /// </summary>
    private static DenialCode ToDenialCode(string code)
    {
        if (!Enum.TryParse<TunnelDenial>(code, ignoreCase: true, out var denial))
        {
            return DenialCode.Unspecified;
        }

        return denial switch
        {
            TunnelDenial.TokenInvalid => DenialCode.TokenInvalid,
            TunnelDenial.TokenRevoked => DenialCode.TokenRevoked,
            TunnelDenial.TokenExpired => DenialCode.TokenExpired,
            TunnelDenial.EmailNotVerified => DenialCode.EmailNotVerified,
            TunnelDenial.SubdomainInvalid => DenialCode.SubdomainInvalid,
            TunnelDenial.SubdomainNotOwned => DenialCode.SubdomainNotOwned,
            TunnelDenial.SubdomainBusy => DenialCode.SubdomainBusy,
            TunnelDenial.DomainNotVerified => DenialCode.DomainNotVerified,
            TunnelDenial.QuotaTunnelsExceeded => DenialCode.QuotaTunnelsExceeded,
            TunnelDenial.PlanSuspended => DenialCode.PlanSuspended,
            _ => DenialCode.Unspecified,
        };
    }
}
