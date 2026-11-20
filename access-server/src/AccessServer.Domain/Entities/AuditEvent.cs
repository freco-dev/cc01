namespace AccessServer.Domain.Entities;

/// <summary>
/// Minimal audit yozuvi. Tenant va foydalanuvchiga FK yo'q: yozuv ular
/// o'chirilgandan keyin ham saqlanib qolishi kerak.
/// </summary>
public sealed class AuditEvent : Entity
{
    public int? TenantId { get; set; }

    public int? UserId { get; set; }

    /// <summary>Kim bajardi, masalan "operator:aziz". Email yozilmaydi.</summary>
    public required string Actor { get; set; }

    /// <summary>Nima bajarildi, masalan "plan.changed".</summary>
    public required string Action { get; set; }

    /// <summary>Nimaga nisbatan, masalan "tenant:t_9f3a".</summary>
    public required string Target { get; set; }

    public string? Ip { get; set; }

    /// <summary>Qo'shimcha ma'lumot (jsonb). Shaxsiy ma'lumot yozilmaydi.</summary>
    public string? Metadata { get; set; }
}
