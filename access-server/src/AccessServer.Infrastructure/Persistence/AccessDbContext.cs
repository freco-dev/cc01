using AccessServer.Application.Abstractions;
using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Infrastructure.Persistence;

public sealed class AccessDbContext : DbContext, IAccessDbContext
{
    private readonly TimeProvider _timeProvider;

    public AccessDbContext(DbContextOptions<AccessDbContext> options, TimeProvider timeProvider)
        : base(options)
    {
        _timeProvider = timeProvider;
    }

    public DbSet<Tenant> Tenants => Set<Tenant>();

    public DbSet<User> Users => Set<User>();

    public DbSet<ApiToken> ApiTokens => Set<ApiToken>();

    public DbSet<Subdomain> Subdomains => Set<Subdomain>();

    public DbSet<UserVerificationToken> UserVerificationTokens => Set<UserVerificationToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AccessDbContext).Assembly);
        base.OnModelCreating(modelBuilder);
    }

    public override int SaveChanges()
    {
        StampTimestamps();
        return base.SaveChanges();
    }

    public override Task<int> SaveChangesAsync(
        bool acceptAllChangesOnSuccess,
        CancellationToken cancellationToken = default)
    {
        StampTimestamps();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    /// <summary>
    /// CreatedAt/UpdatedAt ni markazda to'ldiradi — har bir use-case'da qo'lda
    /// yozilsa, ertami-kechmi biror joyda unutiladi.
    /// </summary>
    private void StampTimestamps()
    {
        var now = _timeProvider.GetUtcNow();

        foreach (var entry in ChangeTracker.Entries<Entity>())
        {
            switch (entry.State)
            {
                case EntityState.Added:
                    entry.Entity.CreatedAt = now;
                    entry.Entity.UpdatedAt = now;
                    break;

                case EntityState.Modified:
                    // CreatedAt o'zgarmasligi kafolatlanadi: kimdir uni
                    // qo'lda o'zgartirgan bo'lsa ham yozib yuborilmaydi.
                    entry.Property(e => e.CreatedAt).IsModified = false;
                    entry.Entity.UpdatedAt = now;
                    break;
            }
        }
    }
}
