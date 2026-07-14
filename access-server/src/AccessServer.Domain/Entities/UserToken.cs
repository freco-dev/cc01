namespace AccessServer.Domain.Entities;

public sealed class UserToken : Entity
{
    public int UserId { get; set; }

    public required User User { get; set; }

    public required string Token { get; set; }

    public required string SubDomain { get; set; }

    public TimeSpan ExpiresIn { get; set; }
}