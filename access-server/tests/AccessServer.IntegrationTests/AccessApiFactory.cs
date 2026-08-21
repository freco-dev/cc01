using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AccessServer.IntegrationTests;

/// <summary>
/// Haqiqiy HTTP quvuri orqali test qiladi: routing, autentifikatsiya,
/// claim'lar, model binding va xato → status kodi xaritalanishi.
///
/// Handler'ni to'g'ridan-to'g'ri chaqiradigan testlar bu qatlamni ko'rmaydi —
/// masalan JWT'ning kiruvchi claim nomlarini o'zgartirishi faqat shu yerda
/// aniqlanadi.
/// </summary>
public sealed class AccessApiFactory(
    string connectionString,
    IDictionary<string, string?>? extraConfiguration = null)
    : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            var settings = new Dictionary<string, string?>
            {
                ["ConnectionStrings:Access"] = connectionString,
                ["Jwt:SigningKey"] = "test-signing-key-at-least-32-characters-long-0123456789",
                ["Jwt:Issuer"] = "cc01-access-test",
                ["Jwt:Audience"] = "cc01-dashboard-test",
                ["Jwt:LifetimeMinutes"] = "60",
            };

            foreach (var (key, value) in extraConfiguration ?? new Dictionary<string, string?>())
            {
                settings[key] = value;
            }

            config.AddInMemoryCollection(settings);
        });

        // ⚠️ ConfigureAppConfiguration Program.cs tanasidan KEYIN qo'llanadi.
        // Startup paytida o'qiladigan sozlamalar (qaysi OAuth sxemasi
        // ro'yxatga olinishi) u yerdan ko'rinmaydi — shuning uchun ular
        // qo'shimcha ravishda UseSetting orqali ham beriladi.
        foreach (var (key, value) in extraConfiguration ?? new Dictionary<string, string?>())
        {
            builder.UseSetting(key, value);
        }

        builder.ConfigureServices(services =>
        {
            // Tasdiqlash tokenini log'dan emas, to'g'ridan-to'g'ri olish uchun.
            services.AddSingleton<RecordingEmailSender>();
            services.AddSingleton<Application.Abstractions.IEmailSender>(
                sp => sp.GetRequiredService<RecordingEmailSender>());
        });
    }
}
