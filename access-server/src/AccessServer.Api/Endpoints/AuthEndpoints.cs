using AccessServer.Api.Common;
using AccessServer.Application.Auth;

namespace AccessServer.Api.Endpoints;

public sealed record RegisterRequest(string FullName, string Email, string Password, bool Subscribe);

public sealed record VerifyEmailRequest(string Token);

public sealed record LoginRequest(string Email, string Password);

public static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/auth").WithTags("Auth");

        group.MapPost("/register", async (
            RegisterRequest request,
            RegisterUserHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(
                new RegisterUserCommand(
                    request.FullName, request.Email, request.Password, request.Subscribe),
                cancellationToken);

            return result.IsSuccess
                ? Results.Created(
                    $"/v1/tenants/{result.Value.TenantSlug}",
                    new { userId = result.Value.UserId, tenantSlug = result.Value.TenantSlug })
                : result.Error!.ToProblem();
        })
        .WithSummary("Yangi hisob yaratadi va tasdiqlash xatini yuboradi");

        group.MapPost("/verify-email", async (
            VerifyEmailRequest request,
            VerifyEmailHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(
                new VerifyEmailCommand(request.Token), cancellationToken);

            return result.IsSuccess ? Results.NoContent() : result.Error!.ToProblem();
        })
        .WithSummary("Email tasdiqlash tokenini ishlatadi");

        group.MapPost("/login", async (
            LoginRequest request,
            LoginHandler handler,
            CancellationToken cancellationToken) =>
        {
            var result = await handler.HandleAsync(
                new LoginCommand(request.Email, request.Password), cancellationToken);

            return result.IsSuccess
                ? Results.Ok(new
                {
                    accessToken = result.Value.AccessToken,
                    expiresAt = result.Value.ExpiresAt,
                    emailVerified = result.Value.EmailVerified,
                    tenantSlug = result.Value.TenantSlug,
                })
                : result.Error!.ToProblem();
        })
        .WithSummary("Dashboard sessiyasi uchun JWT beradi");

        return app;
    }
}
