namespace AccessServer.Domain.Enums;

public enum SubscriptionStatus
{
    Active = 0,

    /// <summary>
    /// Bekor qilingan — tenant Free limitlariga tushadi. Hozircha faqat
    /// EffectivePlanResolver hisobga oladi; uni o'rnatadigan oqim Faza 3
    /// billing bilan keladi.
    /// </summary>
    Canceled = 1,
}
