namespace AccessServer.Application.Abstractions;

public interface IPasswordHasher
{
    string Hash(string password);

    /// <summary>
    /// Doimiy vaqtda solishtiradi. `needsRehash` true bo'lsa saqlangan hash
    /// eskirgan parametrlar bilan yaratilgan — muvaffaqiyatli logindan keyin
    /// yangilash mumkin.
    /// </summary>
    bool Verify(string password, string hash, out bool needsRehash);

    /// <summary>
    /// Haqiqiy formatdagi, lekin hech qanday parolga mos kelmaydigan hash.
    /// Foydalanuvchi topilmaganda ham Verify chaqirilishi uchun kerak —
    /// aks holda javob vaqti hisob mavjudligini oshkor qiladi.
    /// Format faqat implementatsiyaga ma'lum, shuning uchun shu yerda.
    /// </summary>
    string DummyHash { get; }
}
