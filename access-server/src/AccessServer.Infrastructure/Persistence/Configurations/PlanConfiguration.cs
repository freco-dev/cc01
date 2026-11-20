using AccessServer.Domain.Entities;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessServer.Infrastructure.Persistence.Configurations;

internal sealed class PlanConfiguration : IEntityTypeConfiguration<Plan>
{
    /// <summary>
    /// Seed vaqti qat'iy: HasData har migratsiyada qiymatlarni solishtiradi,
    /// `DateTimeOffset.UtcNow` bo'lsa har safar yangi UpdateData chiqadi.
    /// </summary>
    private static readonly DateTimeOffset SeededAt = new(2026, 11, 20, 0, 0, 0, TimeSpan.Zero);

    public void Configure(EntityTypeBuilder<Plan> builder)
    {
        builder.HasKey(p => p.Id);

        // Seed qatorlari 1–3 id'larni oshkora oladi. Identity 100 dan
        // boshlanadi — keyin qo'shilgan tarif seed bilan to'qnashmaydi.
        builder.Property(p => p.Id)
            .UseIdentityByDefaultColumn()
            .HasIdentityOptions(startValue: 100);

        // Enum matn sifatida — tenants.plan bilan bir xil konvensiya.
        builder.Property(p => p.Code).HasConversion<string>().HasMaxLength(20);
        builder.Property(p => p.Name).HasMaxLength(40).IsRequired();

        builder.HasIndex(p => p.Code).IsUnique();

        builder.ToTable(t => t.HasCheckConstraint(
            "ck_plans_limits",
            "max_subdomains >= 1 AND max_tunnels >= 1 AND max_conns_per_tunnel >= 1 AND bandwidth_bps >= 0"));

        // Qiymatlar Faza 0 dagi kod ichidagi katalogga teng — mavjud
        // tenantlar uchun hech narsa o'zgarmaydi. Seed'ni tahrirlash yangi
        // UpdateData migratsiyasini talab qiladi; bazada qo'lda o'zgartirilgan
        // qiymat modeldan farqlanib qoladi.
        builder.HasData(
            new Plan
            {
                Id = 1,
                Code = PlanCode.Free,
                Name = "Free",
                MaxSubdomains = 1,
                MaxTunnels = 1,
                MaxConnsPerTunnel = 24,
                BandwidthBps = 100_000_000,
                CreatedAt = SeededAt,
                UpdatedAt = SeededAt,
            },
            new Plan
            {
                Id = 2,
                Code = PlanCode.Pro,
                Name = "Pro",
                MaxSubdomains = 10,
                MaxTunnels = 10,
                MaxConnsPerTunnel = 128,
                BandwidthBps = 1_000_000_000,
                CreatedAt = SeededAt,
                UpdatedAt = SeededAt,
            },
            new Plan
            {
                Id = 3,
                Code = PlanCode.Enterprise,
                Name = "Enterprise",
                MaxSubdomains = 100,
                MaxTunnels = 100,
                MaxConnsPerTunnel = 1024,
                BandwidthBps = 0,  // 0 = cheklanmagan
                CreatedAt = SeededAt,
                UpdatedAt = SeededAt,
            });
    }
}
