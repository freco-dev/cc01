namespace AccessServer.Application.Authentication;

public sealed record RegisterRequest(string FullName, string Email, string Password, bool Subscribe = false);

public sealed record SignInRequest(string Email, string Password);

public sealed record VerifyEmailRequest(string Email, string VerificationCode);

public sealed record RefreshTokenRequest(string Email, string RefreshToken);

public sealed record CheckEmailRequest(string Email);

public sealed record UserResponse(int Id, string FullName, string Email, bool Verified, bool Subscribe);

public sealed record TokenPairResponse(string AccessToken, string RefreshToken, DateTimeOffset AccessTokenExpiresAt, DateTimeOffset RefreshTokenExpiresAt);

public sealed record AuthSessionResponse(UserResponse User, TokenPairResponse Tokens);

public sealed record RegistrationResponse(UserResponse User, string VerificationCode);

public sealed record VerificationResponse(UserResponse User, TokenPairResponse? Tokens);

public sealed record EmailCheckResponse(string Email, bool Exists, bool Verified);

public interface IAuthService
{
    Task<RegistrationResponse> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

    Task<AuthSessionResponse> SignInAsync(SignInRequest request, CancellationToken cancellationToken = default);

    Task<VerificationResponse> VerifyEmailAsync(VerifyEmailRequest request, CancellationToken cancellationToken = default);

    Task<AuthSessionResponse> RefreshAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default);

    Task<EmailCheckResponse> CheckEmailAsync(CheckEmailRequest request, CancellationToken cancellationToken = default);
}