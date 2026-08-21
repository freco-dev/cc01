using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessServer.Infrastructure.Persistence.Configurations;

internal sealed class SubdomainConfiguration : IEntityTypeConfiguration<Subdomain>
{
    public void Configure(EntityTypeBuilder<Subdomain> builder)
    {
        builder.HasKey(s => s.Id);

        // 38 — proto/cc01/v1/tunnel.proto dagi yagona manbadan.
        builder.Property(s => s.Name).HasMaxLength(38).IsRequired();
        builder.Property(s => s.Status).HasConversion<string>().HasMaxLength(20);

        // Global unikal: subdomain butun platformada bitta tenantga tegishli.
        builder.HasIndex(s => s.Name).IsUnique();
        builder.HasIndex(s => s.TenantId);

        builder.HasOne(s => s.Tenant)
            .WithMany(t => t.Subdomains)
            .HasForeignKey(s => s.TenantId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
