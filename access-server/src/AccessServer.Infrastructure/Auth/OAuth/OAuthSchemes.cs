namespace AccessServer.Infrastructure.Auth.OAuth;

public static class OAuthSchemes
{
    /// <summary>
    /// Provayderdan qaytgan natijani vaqtincha ushlab turadigan cookie sxemasi.
    /// U foydalanuvchi sessiyasi EMAS: bir marta o'qiladi, JWT beriladi va
    /// darhol o'chiriladi. Shuning uchun umri ham qisqa.
    /// </summary>
    public const string External = "External";

    public const string Github = "Github";

    public const string Google = "Google";
}
