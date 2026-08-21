namespace AccessServer.Domain.Enums;

public enum TenantStatus
{
    Active = 0,

    /// <summary>To'lov yoki abuse sababli to'xtatilgan — yangi tunnel ochilmaydi.</summary>
    Suspended = 1,

    Deleted = 2,
}
