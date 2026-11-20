using AccessServer.Domain.Entities;

namespace AccessServer.Application.Plans;

/// <param name="MaxConnectionsPerTunnel">
/// core-server'dagi qattiq yozilgan 24 ning o'rnini bosadi (Faza 0.C).
/// </param>
/// <param name="BandwidthBps">0 = cheklanmagan.</param>
public readonly record struct PlanLimits(
    int MaxSubdomains,
    int MaxTunnels,
    int MaxConnectionsPerTunnel,
    long BandwidthBps);

public static class PlanLimitsExtensions
{
    public static PlanLimits ToLimits(this Plan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        return new PlanLimits(
            plan.MaxSubdomains,
            plan.MaxTunnels,
            plan.MaxConnsPerTunnel,
            plan.BandwidthBps);
    }
}
