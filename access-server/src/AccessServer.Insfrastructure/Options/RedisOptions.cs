namespace AccessServer.Insfrastructure.Options;

public sealed class RedisOptions
{
    public required string Configuration { get; init; }

    public string InstanceName { get; init; } = "accessserver";
}