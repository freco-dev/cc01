using System.Security.Claims;
using AccessServer.Api.Common;
using AccessServer.Application.Usage;

namespace AccessServer.Api.Endpoints;

public static class UsageEndpoints
{
    public static IEndpointRouteBuilder MapUsageEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/usage").RequireAuthorization().WithTags("Usage");

        // from/to string sifatida olinadi va handler'da tahlil qilinadi:
        // noto'g'ri qiymat ham USAGE_RANGE_INVALID beradi (framework'ning
        // umumiy 400'i emas). Tenant — faqat JWT'dan (A-S15).
        group.MapGet("/", async (
            string? from,
            string? to,
            ClaimsPrincipal user,
            GetUsageHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(
                new GetUsageQuery(user.GetTenantId(), from, to),
                cancellationToken);

            if (!result.IsSuccess)
            {
                return result.Error!.ToProblem();
            }

            var view = result.Value;
            return Results.Ok(new
            {
                from = view.From,
                to = view.To,
                totals = Amounts(view.Totals),
                daily = view.Daily.Select(day => new
                {
                    date = day.Date.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
                    bytesIn = day.Amounts.BytesIn,
                    bytesOut = day.Amounts.BytesOut,
                    connections = day.Amounts.Connections,
                    rejected = day.Amounts.Rejected,
                    tunnelHours = day.Amounts.TunnelHours,
                }),
            });
        })
        .WithSummary("Bayt, ulanish va tunnel-soat: jami va UTC kunlari bo'yicha");

        return app;
    }

    private static object Amounts(UsageAmountsView amounts) => new
    {
        bytesIn = amounts.BytesIn,
        bytesOut = amounts.BytesOut,
        connections = amounts.Connections,
        rejected = amounts.Rejected,
        tunnelHours = amounts.TunnelHours,
    };
}
