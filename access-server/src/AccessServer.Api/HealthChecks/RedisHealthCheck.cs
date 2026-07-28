using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AccessServer.Api.HealthChecks;

public sealed class RedisHealthCheck : IHealthCheck
{
    private static readonly DistributedCacheEntryOptions CacheOptions = new()
    {
        AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(5)
    };

    private readonly IDistributedCache _cache;

    public RedisHealthCheck(IDistributedCache cache)
    {
        _cache = cache;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var key = $"health-check:{Guid.NewGuid():N}";
        var value = Guid.NewGuid().ToString("N");

        try
        {
            await _cache.SetStringAsync(key, value, CacheOptions, cancellationToken);
            var readValue = await _cache.GetStringAsync(key, cancellationToken);
            await _cache.RemoveAsync(key, cancellationToken);

            return string.Equals(value, readValue, StringComparison.Ordinal)
                ? HealthCheckResult.Healthy("Redis cache is healthy.")
                : HealthCheckResult.Unhealthy("Redis cache returned an unexpected value.");
        }
        catch (Exception exception)
        {
            return HealthCheckResult.Unhealthy("Redis health check failed.", exception);
        }
    }
}