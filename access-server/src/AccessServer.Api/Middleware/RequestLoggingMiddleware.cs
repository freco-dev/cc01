namespace AccessServer.Api.Middleware;

public sealed class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var start = DateTimeOffset.UtcNow;
        await _next(context);
        var elapsed = DateTimeOffset.UtcNow - start;

        _logger.LogInformation("{Method} {Path} responded {StatusCode} in {ElapsedMilliseconds}ms",
            context.Request.Method,
            context.Request.Path,
            context.Response.StatusCode,
            elapsed.TotalMilliseconds.ToString("0.0"));
    }
}