using System.Net.Mail;
using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Domain.Entities;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Auth;

public sealed record RegisterUserCommand(
    string FullName,
    string Email,
    string Password,
    bool Subscribe);

public sealed record RegisterUserResult(int UserId, string TenantSlug);

public sealed class RegisterUserHandler(
    IAccessDbContext db,
    IPasswordHasher passwordHasher,
    IVerificationTokenFactory verificationTokens,
    IEmailSender emailSender,
    TimeProvider timeProvider)
{
    public const int MinPasswordLength = 12;

    public static readonly TimeSpan VerificationTokenLifetime = TimeSpan.FromHours(24);

    public async Task<Result<RegisterUserResult>> HandleAsync(
        RegisterUserCommand command,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.FullName))
        {
            return AuthErrors.FullNameRequired;
        }

        if (!TryNormalizeEmail(command.Email, out var email))
        {
            return AuthErrors.EmailInvalid;
        }

        if (command.Password.Length < MinPasswordLength)
        {
            return AuthErrors.PasswordTooShort;
        }

        if (await db.Users.AnyAsync(u => u.Email == email, cancellationToken))
        {
            return AuthErrors.EmailTaken;
        }

        var now = timeProvider.GetUtcNow();
        var fullName = command.FullName.Trim();

        // Har bir foydalanuvchi uchun shaxsiy tenant. Jamoa qo'shilganda
        // shu tenant jamoa tenantiga aylanadi — migratsiya kerak emas.
        var tenant = new Tenant
        {
            Slug = TenantSlug.Generate(),
            Name = fullName,
            Plan = PlanCode.Free,
            Status = TenantStatus.Active,
        };

        var user = new User
        {
            Tenant = tenant,
            FullName = fullName,
            Email = email,
            PasswordHash = passwordHasher.Hash(command.Password),
            Status = UserStatus.Active,
            Subscribe = command.Subscribe,
        };

        var generated = verificationTokens.Create();
        var verification = new UserVerificationToken
        {
            User = user,
            Purpose = VerificationPurpose.EmailVerification,
            TokenHash = generated.Hash,
            ExpiresAt = now + VerificationTokenLifetime,
        };

        db.Tenants.Add(tenant);
        db.Users.Add(user);
        db.UserVerificationTokens.Add(verification);

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // Yuqoridagi AnyAsync bilan SaveChanges orasida boshqa so'rov
            // bir xil emailni yozib ulgurishi mumkin. Unique indeks buni
            // ushlab qoladi; foydalanuvchiga bir xil xato qaytariladi.
            return AuthErrors.EmailTaken;
        }

        // Xat yuborish muvaffaqiyatsiz bo'lsa ham ro'yxatdan o'tish bekor
        // qilinmaydi — foydalanuvchi tasdiqlash xatini qayta so'rashi mumkin.
        await emailSender.SendEmailVerificationAsync(
            email, fullName, generated.Secret, cancellationToken);

        return new RegisterUserResult(user.Id, tenant.Slug);
    }

    private static bool TryNormalizeEmail(string? raw, out string email)
    {
        email = string.Empty;

        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var trimmed = raw.Trim();

        // MailAddress qo'lda yozilgan regexdan ancha ishonchli.
        if (!MailAddress.TryCreate(trimmed, out var parsed) || parsed.Address != trimmed)
        {
            return false;
        }

        email = trimmed.ToLowerInvariant();
        return email.Length <= 254;
    }
}
