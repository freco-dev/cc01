using AccessServer.Domain.Enums;

namespace AccessServer.Domain.Entities;

/// <summary>
/// Izolyatsiya chegarasi. Subdomain, token va kvota tenantga tegishli —
/// foydalanuvchiga emas. Ro'yxatdan o'tishda har bir foydalanuvchi uchun
/// shaxsiy tenant avtomatik yaratiladi; jamoa qo'shish keyinroq shu modelning
/// ustiga qo'shiladi va migratsiya talab qilmaydi.
/// </summary>
public sealed class Tenant : Entity
{
    /// <summary>Tashqi identifikator, masalan "t_9f3a". Barqaror va oshkora.</summary>
    public required string Slug { get; set; }

    public required string Name { get; set; }

    public PlanCode Plan { get; set; } = PlanCode.Free;

    public TenantStatus Status { get; set; } = TenantStatus.Active;

    public ICollection<User> Users { get; set; } = [];

    public ICollection<ApiToken> Tokens { get; set; } = [];

    public ICollection<Subdomain> Subdomains { get; set; } = [];
}
