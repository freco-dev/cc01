using AccessServer.Application.Authentication;

namespace AccessServer.Api.Tests;

public sealed class FakeAuthService : IAuthService
{
    public Task<RegistrationResponse> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        var user = new UserResponse(1, request.FullName, request.Email, false, request.Subscribe);
        return Task.FromResult(new RegistrationResponse(user, "123456"));
    }

    public Task<AuthSessionResponse> SignInAsync(SignInRequest request, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(CreateSession(request.Email));
    }

    public Task<VerificationResponse> VerifyEmailAsync(VerifyEmailRequest request, CancellationToken cancellationToken = default)
    {
        var user = new UserResponse(1, "Test User", request.Email, true, false);
        return Task.FromResult(new VerificationResponse(user, CreateTokens()));
    }

    public Task<AuthSessionResponse> RefreshAsync(RefreshTokenRequest request, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(CreateSession(request.Email));
    }

    public Task<EmailCheckResponse> CheckEmailAsync(CheckEmailRequest request, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new EmailCheckResponse(request.Email.ToLowerInvariant(), true, true));
    }

    private static AuthSessionResponse CreateSession(string email)
    {
        var user = new UserResponse(1, "Test User", email, true, false);
        return new AuthSessionResponse(user, CreateTokens());
    }

    private static TokenPairResponse CreateTokens()
    {
        var now = DateTimeOffset.UtcNow;
        return new TokenPairResponse("access-token", "refresh-token", now.AddMinutes(60), now.AddDays(30));
    }
}