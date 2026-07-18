using AccessServer.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Insfrastructure.Persistence;

public sealed class AccessServerDbContext : DbContext
{
    public AccessServerDbContext(DbContextOptions<AccessServerDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();

    public DbSet<UserToken> UserTokens => Set<UserToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<User>(entity =>
        {
            entity.ToTable("users");
            entity.HasKey(user => user.Id);
            entity.Property(user => user.FullName).IsRequired().HasMaxLength(200);
            entity.Property(user => user.Email).IsRequired().HasMaxLength(320);
            entity.HasIndex(user => user.Email).IsUnique();
            entity.Property(user => user.PasswordHash).IsRequired().HasMaxLength(500);
            entity.Property(user => user.EmailVerificationTokenHash).HasMaxLength(500);
            entity.Property(user => user.Verified).HasDefaultValue(false);
            entity.Property(user => user.Subscribe).HasDefaultValue(false);
            entity.HasMany(user => user.Tokens)
                .WithOne(token => token.User)
                .HasForeignKey(token => token.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<UserToken>(entity =>
        {
            entity.ToTable("user_tokens");
            entity.HasKey(token => token.Id);
            entity.Property(token => token.TokenHash).IsRequired().HasMaxLength(500);
            entity.Property(token => token.TokenType).IsRequired().HasMaxLength(50);
            entity.HasIndex(token => token.TokenHash).IsUnique();
            entity.Property(token => token.RevokedAt);
            entity.Property(token => token.ReplacedByTokenHash).HasMaxLength(500);
        });
    }
}