using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Auth;

public sealed record VerifyEmailCommand(string Token);

public sealed class VerifyEmailHandler(
    IAccessDbContext db,
    IVerificationTokenFactory verificationTokens,
    TimeProvider timeProvider)
{
    public async Task<Result> HandleAsync(
        VerifyEmailCommand command,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.Token))
        {
            return AuthErrors.VerificationTokenInvalid;
        }

        // Qidiruv hash bo'yicha: xom token bazada yo'q.
        var hash = verificationTokens.ComputeHash(command.Token);

        var verification = await db.UserVerificationTokens
            .Include(t => t.User)
            .SingleOrDefaultAsync(
                t => t.TokenHash == hash && t.Purpose == VerificationPurpose.EmailVerification,
                cancellationToken);

        var now = timeProvider.GetUtcNow();

        if (verification is null || !verification.IsUsableAt(now))
        {
            return AuthErrors.VerificationTokenInvalid;
        }

        verification.ConsumedAt = now;

        // Idempotent: allaqachon tasdiqlangan bo'lsa birinchi tasdiqlash
        // vaqti saqlanadi.
        verification.User.EmailVerifiedAt ??= now;

        await db.SaveChangesAsync(cancellationToken);
        return Result.Success();
    }
}
