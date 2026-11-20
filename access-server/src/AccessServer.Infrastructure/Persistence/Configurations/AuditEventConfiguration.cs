using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessServer.Infrastructure.Persistence.Configurations;

internal sealed class AuditEventConfiguration : IEntityTypeConfiguration<AuditEvent>
{
    public void Configure(EntityTypeBuilder<AuditEvent> builder)
    {
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Actor).HasMaxLength(64).IsRequired();
        builder.Property(e => e.Action).HasMaxLength(64).IsRequired();
        builder.Property(e => e.Target).HasMaxLength(128).IsRequired();

        // IPv6 matn ko'rinishining eng uzun shakli — 45 belgi.
        builder.Property(e => e.Ip).HasMaxLength(45);
        builder.Property(e => e.Metadata).HasColumnType("jsonb");

        // Navigatsiya yo'q — FK ham yo'q (ataylab, AuditEvent izohiga qarang).
        // Tipik so'rov: "shu tenant bo'yicha oxirgi hodisalar".
        builder.HasIndex(e => new { e.TenantId, e.CreatedAt });
    }
}
