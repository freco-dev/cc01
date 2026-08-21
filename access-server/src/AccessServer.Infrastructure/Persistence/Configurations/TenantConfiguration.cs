using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessServer.Infrastructure.Persistence.Configurations;

internal sealed class TenantConfiguration : IEntityTypeConfiguration<Tenant>
{
    public void Configure(EntityTypeBuilder<Tenant> builder)
    {
        builder.HasKey(t => t.Id);

        builder.Property(t => t.Slug).HasMaxLength(32).IsRequired();
        builder.Property(t => t.Name).HasMaxLength(120).IsRequired();

        // Enumlar matn sifatida saqlanadi: bazaga qarab ma'no tushunarli
        // bo'ladi va enum a'zolari tartibi o'zgarsa ma'lumot buzilmaydi.
        builder.Property(t => t.Plan).HasConversion<string>().HasMaxLength(20);
        builder.Property(t => t.Status).HasConversion<string>().HasMaxLength(20);

        builder.HasIndex(t => t.Slug).IsUnique();
    }
}
