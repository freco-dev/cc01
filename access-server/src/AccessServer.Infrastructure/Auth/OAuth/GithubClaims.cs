namespace AccessServer.Infrastructure.Auth.OAuth;

/// <summary>
/// GitHub uchun standart claim turlari yo'q, shuning uchun o'zimizniki.
/// `/complete` endpointi shu nomlar bo'yicha o'qiydi.
/// </summary>
public static class GithubClaims
{
    public const string Id = "github:id";

    public const string Login = "github:login";

    public const string Name = "github:name";

    public const string Email = "github:email";

    /// <summary>"true" / "false" — GitHub emailni tasdiqlaganmi.</summary>
    public const string EmailVerified = "github:email_verified";
}
