namespace AccessServer.Domain.Enums;

public enum SubdomainStatus
{
    /// <summary>Band qilingan, lekin hozir tunnel ochiq emas.</summary>
    Reserved = 0,

    /// <summary>Hozir aktiv tunnel tomonidan ishlatilmoqda.</summary>
    Active = 1,

    /// <summary>Bo'shatilgan; karantin muddati o'tgach qayta taqsimlanishi mumkin.</summary>
    Released = 2,
}
