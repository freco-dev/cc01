using AccessServer.Domain.Entities;

namespace AccessServer.Application.Abstractions;

public readonly record struct IssuedAccessToken(string Token, DateTimeOffset ExpiresAt);

/// <summary>
/// Dashboard sessiyasi uchun JWT. CLI tokeni bu emas — u opaque va darhol
/// bekor qilinadi (DEV_SPEC §6.3).
/// </summary>
public interface IAccessTokenIssuer
{
    IssuedAccessToken Issue(User user);
}
