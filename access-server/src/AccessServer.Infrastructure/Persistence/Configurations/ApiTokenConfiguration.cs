using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessServer.Infrastructure.Persistence.Configurations;

internal sealed class ApiTokenConfiguration : IEntityTypeConfiguration<ApiToken>
{
    public void Configure(EntityTypeBuilder<ApiToken> builder)
    {
        builder.HasKey(t => t.Id);

        builder.Property(t => t.Prefix).HasMaxLength(32).IsRequired();
        builder.Property(t => t.Name).HasMaxLength(64).IsRequired();

        // SHA-256 — aniq 32 bayt.
        builder.Property(t => t.TokenHash).HasColumnType("bytea").IsRequired();

        // Avtorizatsiyaning issiq yo'li: prefiks bo'yicha bitta qidiruv,
        // keyin hash doimiy vaqtda solishtiriladi.
        builder.HasIndex(t => t.Prefix).IsUnique();
        builder.HasIndex(t => t.TenantId);

        builder.HasOne(t => t.Tenant)
            .WithMany(t => t.Tokens)
            .HasForeignKey(t => t.TenantId)
            .OnDelete(DeleteBehavior.Cascade);

        // Tokenni yaratgan foydalanuvchi o'chsa ham token yozuvi audit uchun
        // qoladi — shuning uchun Restrict.
        builder.HasOne(t => t.CreatedByUser)
            .WithMany()
            .HasForeignKey(t => t.CreatedByUserId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
