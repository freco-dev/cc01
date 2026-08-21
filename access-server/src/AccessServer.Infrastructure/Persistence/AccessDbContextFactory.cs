using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace AccessServer.Infrastructure.Persistence;

/// <summary>
/// `dotnet ef` uchun. Api hostini ko'tarmasdan migratsiya yaratish va
/// qo'llash imkonini beradi — migratsiya DI konfiguratsiyasiga, sirlarga
/// yoki ishga tushirish tartibiga bog'lanib qolmaydi.
/// </summary>
internal sealed class AccessDbContextFactory : IDesignTimeDbContextFactory<AccessDbContext>
{
    public AccessDbContext CreateDbContext(string[] args)
    {
        // Ustuvorlik: CLI argumenti → muhit o'zgaruvchisi → dev default.
        var connectionString =
            args.FirstOrDefault(a => a.StartsWith("--connection=", StringComparison.Ordinal))
                ?.Substring("--connection=".Length)
            ?? Environment.GetEnvironmentVariable("CC01_ACCESS_DB")
            ?? DevelopmentConnectionString;

        var options = new DbContextOptionsBuilder<AccessDbContext>()
            .UseNpgsql(connectionString)
            .UseSnakeCaseNamingConvention()
            .Options;

        return new AccessDbContext(options, TimeProvider.System);
    }

    /// <summary>
    /// deploy/docker-compose.dev.yml dagi qiymatlarga mos. Faqat lokal
    /// ishlab chiqish uchun — bu parol prod'da hech qachon ishlatilmaydi.
    /// </summary>
    private const string DevelopmentConnectionString =
        "Host=127.0.0.1;Port=15432;Database=cc01_access;Username=cc01;Password=cc01_dev_only";
}
