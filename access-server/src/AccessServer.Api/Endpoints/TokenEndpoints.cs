using System.Security.Claims;
using AccessServer.Api.Common;
using AccessServer.Application.Tokens;

namespace AccessServer.Api.Endpoints;

public sealed record CreateTokenRequest(string Name, DateTimeOffset? ExpiresAt);

public static class TokenEndpoints
{
    public static IEndpointRouteBuilder MapTokenEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/tokens").RequireAuthorization().WithTags("Tokens");

        group.MapGet("/", async (
            ClaimsPrincipal user,
            ListApiTokensHandler handler,
            CancellationToken cancellationToken) =>
        {
            var tokens = await handler.HandleAsync(user.GetTenantId(), cancellationToken);
            return Results.Ok(tokens);
        })
        .WithSummary("Tenant tokenlari (sirsiz — faqat prefiks)");

        group.MapPost("/", async (
            CreateTokenRequest request,
            ClaimsPrincipal user,
            CreateApiTokenHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(
                new CreateApiTokenCommand(user.GetUserId(), request.Name, request.ExpiresAt),
                cancellationToken);

            return result.IsSuccess
                ? Results.Created($"/v1/tokens/{result.Value.TokenId}", new
                {
                    id = result.Value.TokenId,
                    prefix = result.Value.Prefix,

                    // Sir FAQAT shu javobda. Qayta ko'rsatib bo'lmaydi —
                    // bazada uning hashi bor, o'zi yo'q.
                    secret = result.Value.Secret,
                })
                : result.Error!.ToProblem();
        })
        .WithSummary("Yangi API token yaratadi (sir bir marta qaytariladi)");

        group.MapDelete("/{id:int}", async (
            int id,
            ClaimsPrincipal user,
            RevokeApiTokenHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(
                new RevokeApiTokenCommand(user.GetTenantId(), id), cancellationToken);

            return result.IsSuccess ? Results.NoContent() : result.Error!.ToProblem();
        })
        .WithSummary("Tokenni bekor qiladi (darhol kuchga kiradi)");

        return app;
    }
}
