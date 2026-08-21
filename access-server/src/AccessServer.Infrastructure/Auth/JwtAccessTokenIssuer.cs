using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AccessServer.Application.Abstractions;
using AccessServer.Domain.Entities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AccessServer.Infrastructure.Auth;

public sealed class JwtAccessTokenIssuer(
    IOptions<JwtOptions> options,
    TimeProvider timeProvider) : IAccessTokenIssuer
{
    private readonly JwtOptions _options = options.Value;

    public IssuedAccessToken Issue(User user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var now = timeProvider.GetUtcNow();
        var expiresAt = now.AddMinutes(_options.LifetimeMinutes);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SigningKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("n")),
            new(JwtRegisteredClaimNames.Email, user.Email),

            // Tenant har bir so'rovda kerak — bazadan qayta o'qimaslik uchun
            // claim'da olib yuriladi.
            new(Cc01Claims.TenantId, user.TenantId.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new(Cc01Claims.EmailVerified, user.IsEmailVerified ? "true" : "false"),
        };

        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expiresAt.UtcDateTime,
            signingCredentials: credentials);

        return new IssuedAccessToken(
            new JwtSecurityTokenHandler().WriteToken(token),
            expiresAt);
    }
}

public static class Cc01Claims
{
    public const string TenantId = "cc01:tenant_id";

    public const string EmailVerified = "cc01:email_verified";
}
