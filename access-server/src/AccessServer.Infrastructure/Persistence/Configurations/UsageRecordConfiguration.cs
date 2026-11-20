using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessServer.Infrastructure.Persistence.Configurations;

internal sealed class UsageRecordConfiguration : IEntityTypeConfiguration<UsageRecord>
{
    public void Configure(EntityTypeBuilder<UsageRecord> builder)
    {
        builder.HasKey(u => u.Id);

        builder.Property(u => u.TunnelId).HasMaxLength(UsageRecord.TunnelIdMaxLength).IsRequired();
        builder.Property(u => u.ReportedBy).HasMaxLength(UsageRecord.ReportedByMaxLength).IsRequired();

        // Idempotentlik kaliti (proto: "window_start + tunnel_id bo'yicha
        // idempotent"). UsageStore'dagi ON CONFLICT aynan shu indeksga
        // tayanadi — nomi yoki ustunlari o'zgarsa, u ham o'zgarishi kerak.
        builder.HasIndex(u => new { u.TunnelId, u.WindowStart }).IsUnique();

        // DEV_SPEC §6.2: dashboard so'rovi "tenant + davr".
        builder.HasIndex(u => new { u.TenantId, u.WindowStart });

        builder.HasOne(u => u.Tenant)
            .WithMany()
            .HasForeignKey(u => u.TenantId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.ToTable(t =>
        {
            t.HasCheckConstraint("ck_usage_records_window", "window_end > window_start");
            t.HasCheckConstraint(
                "ck_usage_records_counters",
                "bytes_in >= 0 AND bytes_out >= 0 AND connections >= 0 AND rejected >= 0");
        });
    }
}
