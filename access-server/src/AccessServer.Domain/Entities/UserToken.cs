namespace AccessServer.Domain.Entities;

public sealed class UserToken : Entity
{
    public int UserId { get; set; }

    public required User User { get; set; }

    public required string TokenHash { get; set; }

    public required string TokenType { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public string? ReplacedByTokenHash { get; set; }
}