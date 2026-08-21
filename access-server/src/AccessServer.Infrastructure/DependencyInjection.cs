using AccessServer.Application.Abstractions;
using AccessServer.Application.Auth;
using AccessServer.Application.Subdomains;
using AccessServer.Application.Tunnels;
using AccessServer.Application.Tokens;
using AccessServer.Infrastructure.Auth;
using AccessServer.Infrastructure.Email;
using AccessServer.Infrastructure.Persistence;
using AccessServer.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AccessServer.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddAccessPersistence(
        this IServiceCollection services,
        string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);

        services.TryAddTimeProvider();

        services.AddDbContext<AccessDbContext>(options => options
            .UseNpgsql(connectionString, npgsql => npgsql
                // Tarmoqdagi qisqa uzilishlarda qayta urinish. Migratsiyalar
                // bilan ishlatilganda ehtiyot bo'lish kerak — ular alohida
                // qadam sifatida bajariladi (DEV_SPEC §6.5 A-S10).
                .EnableRetryOnFailure(maxRetryCount: 3,
                    maxRetryDelay: TimeSpan.FromSeconds(5),
                    errorCodesToAdd: null))
            .UseSnakeCaseNamingConvention());

        // Application qatlami faqat interfeysni ko'radi.
        services.AddScoped<IAccessDbContext>(sp => sp.GetRequiredService<AccessDbContext>());

        return services;
    }

    public static IServiceCollection AddAccessSecurity(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        services.TryAddTimeProvider();

        services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.AddSingleton<IApiTokenFactory, ApiTokenFactory>();
        services.AddSingleton<IVerificationTokenFactory, VerificationTokenFactory>();

        services.AddOptions<JwtOptions>()
            .Bind(configuration.GetSection(JwtOptions.SectionName))
            .ValidateDataAnnotations()
            // Ishga tushishda tekshiriladi: imzolash kaliti yo'q bo'lsa server
            // birinchi so'rovda emas, darhol yiqilishi kerak.
            .ValidateOnStart();

        services.AddSingleton<IAccessTokenIssuer, JwtAccessTokenIssuer>();

        return services;
    }

    /// <summary>
    /// Dev uchun: xat yubormaydi, tasdiqlash tokenini log'ga yozadi.
    /// Prod'da haqiqiy provayder bilan almashtiriladi (Faza 1).
    /// </summary>
    public static IServiceCollection AddDevelopmentEmailSender(this IServiceCollection services)
    {
        services.AddSingleton<IEmailSender, LoggingEmailSender>();
        return services;
    }

    public static IServiceCollection AddAccessUseCases(this IServiceCollection services)
    {
        services.AddScoped<RegisterUserHandler>();
        services.AddScoped<VerifyEmailHandler>();
        services.AddScoped<LoginHandler>();
        services.AddScoped<OAuthLoginHandler>();

        services.AddScoped<CreateApiTokenHandler>();
        services.AddScoped<ListApiTokensHandler>();
        services.AddScoped<RevokeApiTokenHandler>();

        services.AddScoped<AuthorizeTunnelHandler>();

        services.AddScoped<ReserveSubdomainHandler>();
        services.AddScoped<ListSubdomainsHandler>();
        services.AddScoped<ReleaseSubdomainHandler>();

        return services;
    }

    private static void TryAddTimeProvider(this IServiceCollection services)
    {
        // Testlarda soxta TimeProvider bilan almashtirish mumkin bo'lishi uchun
        // ro'yxatga olamiz, lekin allaqachon ro'yxatdan o'tgan bo'lsa tegmaymiz.
        if (services.All(d => d.ServiceType != typeof(TimeProvider)))
        {
            services.AddSingleton(TimeProvider.System);
        }
    }
}
