using AccessServer.Api.Common;
using AccessServer.Application.Plans;
using Microsoft.AspNetCore.Mvc;

namespace AccessServer.Api.Endpoints;

/// <param name="Plan">"free", "pro" yoki "enterprise".</param>
/// <param name="PeriodEnd">null = muddatsiz.</param>
public sealed record ChangePlanRequest(string Plan, DateTimeOffset? PeriodEnd, string? Reason);

/// <summary>
/// Operator API — FAQAT ichki listener'da (DEV_SPEC §6.4, A-S19).
/// Self-service yo'q: billing bo'lmagani uchun u hammaga bepul Enterprise
/// degani bo'lardi. Faza 3 billing ham shu handler'ni chaqiradi.
/// </summary>
public static class InternalPlanEndpoints
{
    public const string ActorHeader = "X-Cc01-Actor";

    public static WebApplication MapInternalPlanEndpoints(
        this WebApplication app,
        string? adminKey)
    {
        ArgumentNullException.ThrowIfNull(app);

        // Kalitsiz yo'l umuman ro'yxatga olinmaydi (deny-by-default):
        // sozlanmagan server 404 qaytaradi, "kalitsiz ochiq" holat bo'lmaydi.
        if (string.IsNullOrEmpty(adminKey))
        {
            app.Logger.LogWarning(
                "Internal:AdminKey sozlanmagan — /internal/v1 operator API'si o'chirilgan "
                + "(tarifni o'zgartirib bo'lmaydi)");
            return app;
        }

        var group = app.MapGroup("/internal/v1")
            .RequireInternalListener()
            .AddEndpointFilter(new AdminKeyFilter(adminKey))
            .WithTags("Internal");

        group.MapPut("/tenants/{slug}/subscription", async (
            string slug,
            ChangePlanRequest request,
            [FromHeader(Name = ActorHeader)] string? actor,
            HttpContext httpContext,
            ChangePlanHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(
                new ChangePlanCommand(
                    slug,
                    request.Plan,
                    request.PeriodEnd,
                    actor ?? string.Empty,
                    request.Reason,
                    httpContext.Connection.RemoteIpAddress?.ToString()),
                cancellationToken);

            return result.IsSuccess
                ? Results.Ok(new
                {
                    tenant = result.Value.Tenant,
                    plan = PlanCodeParser.ToWire(result.Value.Plan),
                    status = result.Value.Status.ToString(),
                    periodStart = result.Value.PeriodStart,
                    periodEnd = result.Value.PeriodEnd,
                    changed = result.Value.Changed,
                })
                : result.Error!.ToProblem();
        })
        .WithSummary("Tenant tarifini o'zgartiradi (operator, audit bilan)");

        return app;
    }
}
