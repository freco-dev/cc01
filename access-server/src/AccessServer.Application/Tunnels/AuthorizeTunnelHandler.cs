using AccessServer.Application.Abstractions;
using AccessServer.Application.Common;
using AccessServer.Application.Subdomains;
using AccessServer.Application.Validation;
using AccessServer.Domain.Entities;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Tunnels;

public sealed record AuthorizeTunnelCommand(
    string Token,
    string? Subdomain,
    string? CustomDomain,
    string? CliVersion,
    string? ClientIp);

/// <summary>
/// Edge server tunnel ochish so'rovini shu yerda avtorizatsiya qiladi
/// (ARCHITECTURE.md §3.4.3). Bu yagona joy — edge o'zi qaror qabul qilmaydi.
/// </summary>
public sealed class AuthorizeTunnelHandler(
    IAccessDbContext db,
    IApiTokenFactory tokenFactory,
    TimeProvider timeProvider)
{
    /// <summary>
    /// Edge natijani shu muddat davomida keshlashi mumkin. Qisqa: token
    /// bekor qilinganda o'zgarish shuncha vaqtda kuchga kiradi.
    /// </summary>
    public const int LeaseTtlSeconds = 60;

    public async Task<Result<AuthorizeTunnelGrant>> HandleAsync(
        AuthorizeTunnelCommand command,
        CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow();

        var token = await ResolveTokenAsync(command.Token, cancellationToken);
        if (token is null)
        {
            return Denied(TunnelDenial.TokenInvalid, "Token topilmadi yoki yaroqsiz.");
        }

        if (token.RevokedAt is not null)
        {
            return Denied(TunnelDenial.TokenRevoked, "Token bekor qilingan.");
        }

        if (token.ExpiresAt is not null && token.ExpiresAt <= now)
        {
            return Denied(TunnelDenial.TokenExpired, "Token muddati tugagan.");
        }

        if (token.Tenant.Status != TenantStatus.Active)
        {
            return Denied(TunnelDenial.PlanSuspended, "Hisob to'xtatilgan.");
        }

        var limits = PlanCatalog.For(token.Tenant.Plan);

        var subdomain = await ResolveSubdomainAsync(token, command.Subdomain, limits, now, cancellationToken);
        if (subdomain.Error is not null)
        {
            return subdomain.Error;
        }

        // Token ishlatilgani qayd etiladi. Bu yozuv har bir tunnel ochishda
        // bo'ladi — aniqligi soniya darajasida bo'lishi yetarli.
        token.LastUsedAt = now;
        await db.SaveChangesAsync(cancellationToken);

        return new AuthorizeTunnelGrant(
            token.CreatedByUserId,
            token.Tenant.Slug,
            token.Tenant.Plan,
            subdomain.Name!,
            limits,
            LeaseTtlSeconds);
    }

    /// <summary>
    /// Prefiks bo'yicha topib, hashni doimiy vaqtda solishtiradi. Sir
    /// bo'yicha qidirish mumkin emas — bazada u yo'q.
    /// </summary>
    private async Task<ApiToken?> ResolveTokenAsync(string? raw, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(raw) || !tokenFactory.TryParsePrefix(raw, out var prefix))
        {
            return null;
        }

        var token = await db.ApiTokens
            .Include(t => t.Tenant)
            .SingleOrDefaultAsync(t => t.Prefix == prefix, cancellationToken);

        if (token is null)
        {
            return null;
        }

        return tokenFactory.HashesEqual(token.TokenHash, tokenFactory.ComputeHash(raw))
            ? token
            : null;
    }

    private async Task<(string? Name, Error? Error)> ResolveSubdomainAsync(
        ApiToken token,
        string? requested,
        PlanLimits limits,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var name = requested?.Trim().ToLowerInvariant();

        if (string.IsNullOrEmpty(name))
        {
            // So'ralmagan bo'lsa — tenantning mavjud subdomainini beramiz.
            var owned = await db.Subdomains
                .Where(s => s.TenantId == token.TenantId && s.Status != SubdomainStatus.Released)
                .OrderBy(s => s.Id)
                .FirstOrDefaultAsync(cancellationToken);

            return owned is null
                ? (null, Denied(TunnelDenial.SubdomainNotOwned,
                    "Subdomain ko'rsatilmagan va hisobda band qilingani yo'q.").Error)
                : (owned.Name, null);
        }

        var validation = SubdomainRules.Validate(name);
        if (validation != SubdomainValidation.Ok)
        {
            return (null, Denied(TunnelDenial.SubdomainInvalid,
                SubdomainErrors.ForValidation(validation).Message).Error);
        }

        var existing = await db.Subdomains
            .SingleOrDefaultAsync(s => s.Name == name, cancellationToken);

        if (existing is not null)
        {
            if (existing.TenantId != token.TenantId)
            {
                return (null, Denied(TunnelDenial.SubdomainNotOwned,
                    $"'{name}' boshqa hisobga tegishli.").Error);
            }

            return (existing.Name, null);
        }

        // Bo'sh nom — kvota ichida bo'lsa shu yerda band qilamiz. Shunda
        // `cc01 tunnel http 8080 --subdomain myapp` dashboardga kirmasdan
        // ishlaydi, lekin nom baribir EGALIK qilinadi: keyingi safar uni
        // boshqa hisob ololmaydi.
        var owns = await db.Subdomains
            .CountAsync(s => s.TenantId == token.TenantId
                             && s.Status != SubdomainStatus.Released, cancellationToken);

        if (owns >= limits.MaxSubdomains)
        {
            return (null, Denied(TunnelDenial.QuotaTunnelsExceeded,
                "Tarif bo'yicha subdomainlar limitiga yetdingiz.").Error);
        }

        db.Subdomains.Add(new Subdomain
        {
            TenantId = token.TenantId,
            Name = name,
            Status = SubdomainStatus.Reserved,
        });

        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // Poyga: boshqa so'rov shu nomni band qilib ulgurdi.
            return (null, Denied(TunnelDenial.SubdomainBusy,
                $"'{name}' hozirgina band qilindi.").Error);
        }

        _ = now;
        return (name, null);
    }

    private static Result<AuthorizeTunnelGrant> Denied(TunnelDenial denial, string message) =>
        new Error(denial.ToString(), message);
}
