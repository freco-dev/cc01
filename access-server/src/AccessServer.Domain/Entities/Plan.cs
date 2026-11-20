using AccessServer.Domain.Enums;

namespace AccessServer.Domain.Entities;

/// <summary>
/// Tarif va uning limitlari. Qiymatlar bazada (HasData bilan seed qilinadi) —
/// kod ichida zaxira nusxa yo'q: yagona manba shu jadval. Jadvaldagi
/// o'zgarish keyingi avtorizatsiyadayoq ko'rinadi.
/// </summary>
public sealed class Plan : Entity
{
    public PlanCode Code { get; set; }

    public required string Name { get; set; }

    public int MaxSubdomains { get; set; }

    /// <summary>Bir vaqtda ochiq tunnellar soni (edge node bo'yicha tekshiriladi).</summary>
    public int MaxTunnels { get; set; }

    public int MaxConnsPerTunnel { get; set; }

    /// <summary>0 = cheklanmagan.</summary>
    public long BandwidthBps { get; set; }
}
