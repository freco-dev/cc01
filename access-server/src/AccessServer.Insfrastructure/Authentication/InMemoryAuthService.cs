using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AccessServer.Application.Authentication;
using AccessServer.Domain.Entities;
using AccessServer.Insfrastructure.Persistence;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

namespace AccessServer.Insfrastructure.Authentication;

public sealed class DatabaseAuthService : IAuthService
{
    private static readonly DistributedCacheEntryOptions EmailCacheOptions = new()
    {
        SlidingExpiration = TimeSpan.FromMinutes(5)
    };

    private readonly JwtOptions _jwtOptions;
    private readonly AccessServerDbContext _dbContext;
    private readonly IDistributedCache _cache;

    public DatabaseAuthService(
        IOptions<JwtOptions> jwtOptions,
        AccessServerDbContext dbContext,
        IDistributedCache cache)
    {
        _jwtOptions = jwtOptions.Value;
        _dbContext = dbContext;
        _cache = cache;
    }

    public async Task<RegistrationResponse> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ValidateEmail(request.Email);
        ValidatePassword(request.Password);

        var normalizedEmail = NormalizeEmail(request.Email);
        var existingUser = await _dbContext.Users.AsNoTracking().AnyAsync(user => user.Email == normalizedEmail, cancellationToken);
        if (existingUser)
        {
            throw new InvalidOperationException("Email is already registered.");
        }

        var verificationCode = GenerateVerificationCode();
        var user = new User
        {
            FullName = request.FullName.Trim(),
            Email = normalizedEmail,
            PasswordHash = HashSecret(request.Password),
            EmailVerificationTokenHash = HashSecret(verificationCode),
            EmailVerificationTokenExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15),
            Verified = false,
            Subscribe = request.Subscribe
        };

        _dbContext.Users.Add(user);
    await _dbContext.SaveChangesAsync(cancellationToken);

        _cache.Remove(GetEmailCheckCacheKey(normalizedEmail));

    return new RegistrationResponse(ToUserResponse(user), verificationCode);
    }

    public async Task<AuthSessionResponse> SignInAsync(SignInRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ValidateEmail(request.Email);

        var normalizedEmail = NormalizeEmail(request.Email);
        var user = await _dbContext.Users
            .Include(current => current.Tokens)
            .SingleOrDefaultAsync(current => current.Email == normalizedEmail, cancellationToken);

        if (user is null || !VerifySecret(request.Password, user.PasswordHash))
        {
            throw new InvalidOperationException("Invalid credentials.");
        }

        if (!user.Verified)
        {
            throw new InvalidOperationException("Email must be verified before sign-in.");
        }

        return await CreateSessionAsync(user, cancellationToken);
    }

    public async Task<VerificationResponse> VerifyEmailAsync(VerifyEmailRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ValidateEmail(request.Email);

        var normalizedEmail = NormalizeEmail(request.Email);
        var user = await _dbContext.Users
            .Include(current => current.Tokens)
            .SingleOrDefaultAsync(current => current.Email == normalizedEmail, cancellationToken);

        if (user is null)
        {
            throw new InvalidOperationException("Email is not registered.");
        }

        var tokenIsExpired = user.EmailVerificationTokenExpiresAt is null || user.EmailVerificationTokenExpiresAt <= DateTimeOffset.UtcNow;
        var tokenMatches = user.EmailVerificationTokenHash is not null && VerifySecret(request.VerificationCode, user.EmailVerificationTokenHash);

        if (tokenIsExpired || !tokenMatches)
        {
            throw new InvalidOperationException("Verification code is invalid or expired.");
        }

        user.Verified = true;
        user.VerifiedAt = DateTimeOffset.UtcNow;
        user.EmailVerificationTokenHash = null;
        user.EmailVerificationTokenExpiresAt = null;

        var response = ToUserResponse(user);
        var session = await CreateSessionAsync(user, cancellationToken);
        _cache.Remove(GetEmailCheckCacheKey(normalizedEmail));

        return new VerificationResponse(response, session.Tokens);
    }

    public async Task<AuthSessionResponse> RefreshAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ValidateEmail(request.Email);

        var normalizedEmail = NormalizeEmail(request.Email);
        var user = await _dbContext.Users
            .Include(current => current.Tokens)
            .SingleOrDefaultAsync(current => current.Email == normalizedEmail, cancellationToken);

        if (user is null)
        {
            throw new InvalidOperationException("Email is not registered.");
        }

        var refreshTokenHash = HashToken(request.RefreshToken);
        var tokenEntity = user.Tokens.SingleOrDefault(token => token.TokenHash == refreshTokenHash && token.TokenType == "refresh");

        if (tokenEntity is null)
        {
            throw new InvalidOperationException("Refresh token is invalid.");
        }

        if (tokenEntity.RevokedAt is not null || tokenEntity.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw new InvalidOperationException("Refresh token is expired.");
        }

        tokenEntity.RevokedAt = DateTimeOffset.UtcNow;
        var session = await CreateSessionAsync(user, cancellationToken);
        tokenEntity.ReplacedByTokenHash = HashToken(session.Tokens.RefreshToken);

        await _dbContext.SaveChangesAsync(cancellationToken);

        return session;
    }

    public async Task<EmailCheckResponse> CheckEmailAsync(CheckEmailRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ValidateEmail(request.Email);

        var normalizedEmail = NormalizeEmail(request.Email);
        var cacheKey = GetEmailCheckCacheKey(normalizedEmail);
        var cached = await _cache.GetStringAsync(cacheKey, cancellationToken);
        if (!string.IsNullOrWhiteSpace(cached))
        {
            var cachedResponse = JsonSerializer.Deserialize<EmailCheckResponse>(cached);
            if (cachedResponse is not null)
            {
                return cachedResponse;
            }
        }

        var user = await _dbContext.Users.AsNoTracking().SingleOrDefaultAsync(current => current.Email == normalizedEmail, cancellationToken);
        var response = new EmailCheckResponse(normalizedEmail, user is not null, user?.Verified ?? false);
        await _cache.SetStringAsync(cacheKey, JsonSerializer.Serialize(response), EmailCacheOptions, cancellationToken);
        return response;
    }

    private async Task<AuthSessionResponse> CreateSessionAsync(User user, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var accessTokenExpiresAt = now.AddMinutes(_jwtOptions.AccessTokenMinutes);
        var refreshTokenExpiresAt = now.AddDays(_jwtOptions.RefreshTokenDays);
        var accessToken = CreateAccessToken(user, accessTokenExpiresAt);
        var refreshToken = GenerateRefreshToken();
        var refreshTokenHash = HashToken(refreshToken);

        var token = new UserToken
        {
            User = user,
            UserId = user.Id,
            TokenHash = refreshTokenHash,
            TokenType = "refresh",
            ExpiresAt = refreshTokenExpiresAt
        };

        user.Tokens.Add(token);
        await _dbContext.SaveChangesAsync(cancellationToken);

        return new AuthSessionResponse(ToUserResponse(user), new TokenPairResponse(accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt));
    }

    private string CreateAccessToken(User user, DateTimeOffset expiresAt)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.SigningKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString(CultureInfo.InvariantCulture)),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Name, user.FullName),
            new("verified", user.Verified.ToString().ToLowerInvariant()),
            new("subscribe", user.Subscribe.ToString().ToLowerInvariant()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture))
        };

        var token = new JwtSecurityToken(
            issuer: _jwtOptions.Issuer,
            audience: _jwtOptions.Audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: expiresAt.UtcDateTime,
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static UserResponse ToUserResponse(User user) => new(user.Id, user.FullName, user.Email, user.Verified, user.Subscribe);

    private static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    private static string GetEmailCheckCacheKey(string email) => $"email-check:{email}";

    private static string GenerateVerificationCode() => RandomNumberGenerator.GetInt32(100000, 999999).ToString(CultureInfo.InvariantCulture);

    private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    private static void ValidateEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
        {
            throw new InvalidOperationException("A valid email is required.");
        }
    }

    private static void ValidatePassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
        {
            throw new InvalidOperationException("Password must be at least 8 characters long.");
        }
    }

    private static string HashSecret(string value)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(value, salt, 100_000, HashAlgorithmName.SHA256, 32);
        return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
    }

    private static string HashToken(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToBase64String(hash);
    }

    private static bool VerifySecret(string value, string hash)
    {
        var parts = hash.Split(':', 2);
        if (parts.Length != 2)
        {
            return false;
        }

        var salt = Convert.FromBase64String(parts[0]);
        var expectedHash = Convert.FromBase64String(parts[1]);
        var actualHash = Rfc2898DeriveBytes.Pbkdf2(value, salt, 100_000, HashAlgorithmName.SHA256, expectedHash.Length);
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }
}