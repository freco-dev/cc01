namespace AccessServer.Application.Abstractions;

public interface IEmailSender
{
    Task SendEmailVerificationAsync(
        string email,
        string fullName,
        string verificationToken,
        CancellationToken cancellationToken = default);
}
