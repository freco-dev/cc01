using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessServer.Infrastructure.Persistence.Configurations;

internal sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.HasKey(u => u.Id);

        builder.Property(u => u.FullName).HasMaxLength(120).IsRequired();
        builder.Property(u => u.Email).HasMaxLength(254).IsRequired();
        builder.Property(u => u.PasswordHash).HasMaxLength(256);
        builder.Property(u => u.GithubId).HasMaxLength(64);
        builder.Property(u => u.GoogleId).HasMaxLength(64);
        builder.Property(u => u.Status).HasConversion<string>().HasMaxLength(20);

        builder.HasIndex(u => u.Email).IsUnique();

        // Provider `sub` bo'yicha qidiruv OAuth callback'da bo'ladi.
        // Filtrlangan unique: null qiymatlar ko'p bo'lishi mumkin.
        builder.HasIndex(u => u.GithubId).IsUnique().HasFilter("github_id IS NOT NULL");
        builder.HasIndex(u => u.GoogleId).IsUnique().HasFilter("google_id IS NOT NULL");

        builder.HasOne(u => u.Tenant)
            .WithMany(t => t.Users)
            .HasForeignKey(u => u.TenantId)
            .OnDelete(DeleteBehavior.Restrict);

        // IsEmailVerified — hisoblanadigan xossa, ustun emas.
        builder.Ignore(u => u.IsEmailVerified);
    }
}
