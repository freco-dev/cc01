using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AccessServer.Infrastructure.Persistence.Configurations;

internal sealed class SubscriptionConfiguration : IEntityTypeConfiguration<Subscription>
{
    public void Configure(EntityTypeBuilder<Subscription> builder)
    {
        builder.HasKey(s => s.Id);

        builder.Property(s => s.Status).HasConversion<string>().HasMaxLength(20);

        // xmin: ikki parallel tarif o'zgarishidan biri
        // DbUpdateConcurrencyException oladi, jimgina ustidan yozilmaydi.
        builder.Property(s => s.Version).IsRowVersion();

        // Bitta tenant — bitta obuna. One-to-one tenant_id ustida unique
        // indeks hosil qiladi.
        builder.HasOne(s => s.Tenant)
            .WithOne(t => t.Subscription)
            .HasForeignKey<Subscription>(s => s.TenantId)
            .OnDelete(DeleteBehavior.Cascade);

        // Ishlatilayotgan tarifni o'chirib bo'lmaydi.
        builder.HasOne(s => s.Plan)
            .WithMany()
            .HasForeignKey(s => s.PlanId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.ToTable(t => t.HasCheckConstraint(
            "ck_subscriptions_period",
            "period_end IS NULL OR period_end > period_start"));
    }
}
