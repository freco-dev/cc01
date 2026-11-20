using AccessServer.Application.Abstractions;
using AccessServer.Domain.Entities;
using AccessServer.Domain.Enums;
using Microsoft.EntityFrameworkCore;

namespace AccessServer.Application.Plans;

public static class PlanQueries
{
    /// <summary>
    /// Free tarif qatori (kuzatiladi — yangi obunaga navigatsiya sifatida
    /// biriktirish mumkin). Kod ichida zaxira qiymat yo'q: qator bo'lmasa bu
    /// konfiguratsiya xatosi, jim "Free 24" emas.
    /// </summary>
    public static Task<Plan> GetFreePlanAsync(
        this IAccessDbContext db,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        return db.Plans.GetFreeAsync(cancellationToken);
    }

    /// <summary>
    /// <see cref="GetFreePlanAsync"/> ning so'rov ustidagi shakli — masalan
    /// <c>db.Plans.AsNoTracking().GetFreeAsync(ct)</c>.
    /// </summary>
    public static async Task<Plan> GetFreeAsync(
        this IQueryable<Plan> plans,
        CancellationToken cancellationToken = default)
    {
        var free = await plans.SingleOrDefaultAsync(p => p.Code == PlanCode.Free, cancellationToken);

        // gRPC'da Internal bo'lib chiqadi; edge buni tarmoq xatosi kabi
        // ko'radi (fail-static) — noto'g'ri sozlama ochiq tunnelni yopmaydi.
        return free ?? throw new InvalidOperationException(
            "plans jadvalida Free yo'q — migratsiya qo'llanmagan");
    }
}
