using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace AccessServer.Api.Middleware;

public sealed class GlobalExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GlobalExceptionMiddleware> _logger;

    public GlobalExceptionMiddleware(RequestDelegate next, ILogger<GlobalExceptionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Unhandled exception processing {Method} {Path}", context.Request.Method, context.Request.Path);

            if (context.Response.HasStarted)
            {
                throw;
            }

            context.Response.ContentType = "application/problem+json";
            context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

            var problem = new ProblemDetails
            {
                Title = "An unexpected error occurred.",
                Detail = exception.Message,
                Status = StatusCodes.Status500InternalServerError,
                Instance = context.Request.Path
            };

            await context.Response.WriteAsync(JsonSerializer.Serialize(problem));
        }
    }
}