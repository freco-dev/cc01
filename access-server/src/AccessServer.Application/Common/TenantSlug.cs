namespace AccessServer.Application.Common;

public static class TenantSlug
{
    /// <summary>
    /// Tashqi identifikator: "t_9f3a1c2b4d5e". Ketma-ket ID emas — tenantlar
    /// sonini va bir-biriga nisbatan yoshini oshkor qilmaydi.
    /// </summary>
    public static string Generate() => "t_" + Guid.NewGuid().ToString("n")[..12];
}
