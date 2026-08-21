using System.Security.Claims;
using AccessServer.Api.Common;
using AccessServer.Application.Subdomains;

namespace AccessServer.Api.Endpoints;

public sealed record ReserveSubdomainRequest(string Name);

public static class SubdomainEndpoints
{
    public static IEndpointRouteBuilder MapSubdomainEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/subdomains").RequireAuthorization().WithTags("Subdomains");

        group.MapGet("/", async (
            ClaimsPrincipal user,
            ListSubdomainsHandler handler,
            CancellationToken cancellationToken) =>
        {
            var items = await handler.HandleAsync(user.GetTenantId(), cancellationToken);
            return Results.Ok(items);
        })
        .WithSummary("Tenantga tegishli subdomainlar");

        group.MapPost("/", async (
            ReserveSubdomainRequest request,
            ClaimsPrincipal user,
            ReserveSubdomainHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(
                new ReserveSubdomainCommand(user.GetTenantId(), request.Name),
                cancellationToken);

            return result.IsSuccess
                ? Results.Created($"/v1/subdomains/{result.Value.Id}", new
                {
                    id = result.Value.Id,
                    name = result.Value.Name,
                    status = result.Value.Status.ToString(),
                })
                : result.Error!.ToProblem();
        })
        .WithSummary("Subdomainni tenantga band qiladi");

        group.MapDelete("/{id:int}", async (
            int id,
            ClaimsPrincipal user,
            ReleaseSubdomainHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(
                new ReleaseSubdomainCommand(user.GetTenantId(), id), cancellationToken);

            return result.IsSuccess ? Results.NoContent() : result.Error!.ToProblem();
        })
        .WithSummary("Subdomainni bo'shatadi (karantinga o'tadi)");

        return app;
    }
}
