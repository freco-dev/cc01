using System.Data.Common;
using AccessServer.Api.Common;
using AccessServer.Application.Common;
using AccessServer.Application.Plans;
using AccessServer.Application.Tunnels;
using AccessServer.Application.Usage;
using AccessServer.Domain.Entities;
using Cc01.V1;
using Grpc.Core;
using Microsoft.EntityFrameworkCore.Storage;

namespace AccessServer.Api.Grpc;

/// <summary>
/// AP ↔ Edge ichki kontrakti (proto/cc01/v1/access.proto).
///
/// Bu servis FAQAT ichki portda ochiladi (Program.cs dagi RequireInternalListener) —
/// internetdan erishib bo'lmaydi. DEV_SPEC §6.4.
/// </summary>
public sealed class TunnelAuthorizationService(
    AuthorizeTunnelHandler authorize,
    RecordUsageHandler recordUsage,
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

    /// <summary>
    /// Edge'ning usage oynalarini saqlaydi (RecordUsageHandler). Javob:
    ///
    ///   OK, accepted = so'rovdagi oynalar soni — qo'shilgan, takror va
    ///       tashlangan (noto'g'ri / tenant noma'lum) birga. Edge ularni
    ///       navbatidan o'chiradi.
    ///   InvalidArgument — 1000 tadan ko'p oyna (edge ≤500 yuboradi).
    ///   Unavailable     — baza xatosi: edge hisobotni saqlab, qayta yuboradi.
    /// </summary>
    public override async Task<ReportUsageResponse> ReportUsage(
        ReportUsageRequest request,
        ServerCallContext context)
    {
        if (request.Windows.Count > RecordUsageHandler.MaxBatchSize)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, UsageErrors.BatchTooLarge.Message));
        }

        var windows = request.Windows
            .Select(w => new UsageWindowInput(
                w.TenantId,
                w.TunnelId,
                w.WindowStart,
                w.WindowEnd,
                w.BytesIn,
                w.BytesOut,
                w.Connections,
                w.Rejected))
            .ToList();

        Result<RecordUsageOutcome> result;
        try
        {
            result = await recordUsage.HandleAsync(
                new RecordUsageCommand(windows, ResolveReporter(context)),
                context.CancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException && IsDatabaseFailure(ex))
        {
            logger.LogWarning(ex,
                "Usage hisoboti saqlanmadi (baza xatosi): {Count} oyna — edge qayta yuboradi",
                windows.Count);

            throw new RpcException(new Status(
                StatusCode.Unavailable,
                "Usage hozircha saqlanmadi. Hisobotni keyinroq qayta yuboring."));
        }

        if (!result.IsSuccess)
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, result.Error!.Message));
        }

        return new ReportUsageResponse { Accepted = (uint)result.Value.Received };
    }

    /// <summary>
    /// Hisobotni kim yubordi: mTLS bo'lsa — klient sertifikatining Subject
    /// CN'i (handshake'da allowlist bo'yicha tekshirilgan), aks holda
    /// "plaintext" (loopback h2c, S-11).
    /// </summary>
    private static string ResolveReporter(ServerCallContext context)
    {
        var certificate = context.GetHttpContext().Connection.ClientCertificate;
        if (certificate is null)
        {
            return UsageRecord.PlaintextReporter;
        }

        // Handshake CN'siz sertifikatni o'tkazmaydi — bu faqat himoya qatlami.
        return InternalTls.GetCommonName(certificate) ?? "unknown";
    }

    /// <summary>
    /// Baza yetib bo'lmasligi yoki so'rov yiqilishi — vaqtinchalik holat:
    /// edge qayta yuboradi. Npgsql xatolari DbException; retry strategiyasi
    /// tugasa RetryLimitExceededException (ichida DbException).
    /// </summary>
    private static bool IsDatabaseFailure(Exception ex)
    {
        for (var current = ex; current is not null; current = current.InnerException)
        {
            if (current is DbException or RetryLimitExceededException or TimeoutException)
            {
                return true;
            }
        }

        return false;
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
