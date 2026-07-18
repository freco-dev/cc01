namespace AccessServer.Domain.Entities;

public sealed class User : Entity
{
    public required string FullName { get; set; }

    public required string Email { get; set; }

    public required string PasswordHash { get; set; }

    public string? EmailVerificationTokenHash { get; set; }

    public DateTimeOffset? EmailVerificationTokenExpiresAt { get; set; }

    public bool Verified { get; set; }

    public DateTimeOffset? VerifiedAt { get; set; }

    public bool Subscribe { get; set; }

    public ICollection<UserToken> Tokens { get; set; } = [];
}