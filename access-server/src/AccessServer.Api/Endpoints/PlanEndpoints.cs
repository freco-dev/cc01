using System.Security.Claims;
using AccessServer.Api.Common;
using AccessServer.Application.Plans;

namespace AccessServer.Api.Endpoints;

public static class PlanEndpoints
{
    public static IEndpointRouteBuilder MapPlanEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/plan").RequireAuthorization().WithTags("Plan");

        group.MapGet("/", async (
            ClaimsPrincipal user,
            GetPlanHandler handler,
            CancellationToken cancellationToken) =>
        {
            var view = await handler.HandleAsync(user.GetTenantId(), cancellationToken);

            return Results.Ok(new
            {
                plan = PlanCodeParser.ToWire(view.Plan),
                source = view.Source.ToString(),
                subscription = view.Subscription is { } s
                    ? new
                    {
                        status = s.Status.ToString(),
                        periodStart = s.PeriodStart,
                        periodEnd = s.PeriodEnd,
                    }
                    : null,
                limits = view.Limits,
                usage = view.Usage,
            });
        })
        .WithSummary("Amaldagi tarif, limitlar va joriy foydalanish");

        return app;
    }
}
