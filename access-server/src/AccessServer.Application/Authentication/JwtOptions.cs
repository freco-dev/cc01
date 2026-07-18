namespace AccessServer.Application.Authentication;

public sealed class JwtOptions
{
    public required string Issuer { get; init; }

    public required string Audience { get; init; }

    public required string SigningKey { get; init; }

    public int AccessTokenMinutes { get; init; } = 60;

    public int RefreshTokenDays { get; init; } = 30;
}