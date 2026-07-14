namespace AccessServer.Domain.Entities;

public sealed class User : Entity
{
    public required string FullName { get; set; }

    public required string Email { get; set; }

    public required string Password { get; set; }

    public string? GithubToken { get; set; }

    public string? GoogleToken { get; set; }

    public bool Verified { get; set; }

    public bool Subscribe { get; set; }

    public ICollection<UserToken> Tokens { get; set; } = [];
}