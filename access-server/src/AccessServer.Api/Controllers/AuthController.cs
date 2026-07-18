using AccessServer.Application.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AccessServer.Api.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult<RegistrationResponse>> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _authService.RegisterAsync(request, cancellationToken);
            return CreatedAtAction(nameof(CheckEmail), new { email = response.User.Email }, response);
        }
        catch (InvalidOperationException exception)
        {
            return Conflict(new ProblemDetails { Title = exception.Message });
        }
    }

    [HttpPost("sign-in")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthSessionResponse>> SignIn([FromBody] SignInRequest request, CancellationToken cancellationToken)
    {
        try
        {
            return Ok(await _authService.SignInAsync(request, cancellationToken));
        }
        catch (InvalidOperationException exception)
        {
            return BadRequest(new ProblemDetails { Title = exception.Message });
        }
    }

    [HttpPost("verify-email")]
    [AllowAnonymous]
    public async Task<ActionResult<VerificationResponse>> VerifyEmail([FromBody] VerifyEmailRequest request, CancellationToken cancellationToken)
    {
        try
        {
            return Ok(await _authService.VerifyEmailAsync(request, cancellationToken));
        }
        catch (InvalidOperationException exception)
        {
            return BadRequest(new ProblemDetails { Title = exception.Message });
        }
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthSessionResponse>> Refresh([FromBody] RefreshTokenRequest request, CancellationToken cancellationToken)
    {
        try
        {
            return Ok(await _authService.RefreshAsync(request, cancellationToken));
        }
        catch (InvalidOperationException exception)
        {
            return BadRequest(new ProblemDetails { Title = exception.Message });
        }
    }

    [HttpGet("email-check")]
    [AllowAnonymous]
    public async Task<ActionResult<EmailCheckResponse>> CheckEmail([FromQuery] string email, CancellationToken cancellationToken)
    {
        try
        {
            return Ok(await _authService.CheckEmailAsync(new CheckEmailRequest(email), cancellationToken));
        }
        catch (InvalidOperationException exception)
        {
            return BadRequest(new ProblemDetails { Title = exception.Message });
        }
    }

    [HttpGet("me")]
    [Authorize]
    public ActionResult<object> Me()
    {
        return Ok(new
        {
            UserId = User.FindFirst("sub")?.Value,
            Email = User.FindFirst("email")?.Value,
            Name = User.FindFirst("name")?.Value,
            Verified = User.FindFirst("verified")?.Value,
            Subscribe = User.FindFirst("subscribe")?.Value
        });
    }
}