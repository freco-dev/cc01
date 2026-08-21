using AccessServer.Application.Abstractions;
using Microsoft.Extensions.Logging;

namespace AccessServer.Infrastructure.Email;

/// <summary>
/// Ishlab chiqish uchun: xat yubormaydi, tasdiqlash havolasini log'ga yozadi.
/// Prod'da haqiqiy provayder bilan almashtiriladi (Faza 1).
///
/// ⚠️ Tokenni log'ga yozadi — shuning uchun faqat Development muhitida
/// ro'yxatga olinadi. Registratsiyani AddAccessInfrastructure hal qiladi.
/// </summary>
public sealed class LoggingEmailSender(ILogger<LoggingEmailSender> logger) : IEmailSender
{
    public Task SendEmailVerificationAsync(
        string email,
        string fullName,
        string verificationToken,
        CancellationToken cancellationToken = default)
    {
        logger.LogInformation(
            "[DEV] Email tasdiqlash — {Email} ({FullName}). Token: {Token}",
            email, fullName, verificationToken);

        return Task.CompletedTask;
    }
}
