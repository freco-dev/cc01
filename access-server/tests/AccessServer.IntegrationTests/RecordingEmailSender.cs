using System.Collections.Concurrent;
using AccessServer.Application.Abstractions;

namespace AccessServer.IntegrationTests;

/// <summary>
/// Yuborilgan tasdiqlash tokenlarini eslab qoladi, shunda test uni
/// "xatdan olib" ishlatishi mumkin.
/// </summary>
public sealed class RecordingEmailSender : IEmailSender
{
    private readonly ConcurrentDictionary<string, string> _tokensByEmail = new(StringComparer.Ordinal);

    public Task SendEmailVerificationAsync(
        string email,
        string fullName,
        string verificationToken,
        CancellationToken cancellationToken = default)
    {
        _tokensByEmail[email] = verificationToken;
        return Task.CompletedTask;
    }

    public string TokenFor(string email) =>
        _tokensByEmail.TryGetValue(email, out var token)
            ? token
            : throw new InvalidOperationException($"{email} uchun tasdiqlash tokeni yuborilmagan.");
}
