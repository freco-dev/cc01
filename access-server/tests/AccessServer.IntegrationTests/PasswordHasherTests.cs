using AccessServer.Infrastructure.Security;
using Xunit;

namespace AccessServer.IntegrationTests;

public sealed class PasswordHasherTests
{
    private readonly Pbkdf2PasswordHasher _hasher = new();

    [Fact]
    public void Hash_then_verify_succeeds()
    {
        var hash = _hasher.Hash("correct horse battery staple");

        Assert.True(_hasher.Verify("correct horse battery staple", hash, out var needsRehash));
        Assert.False(needsRehash);
    }

    [Fact]
    public void Verify_rejects_wrong_password()
    {
        var hash = _hasher.Hash("correct horse battery staple");

        Assert.False(_hasher.Verify("wrong password entirely", hash, out _));
    }

    [Fact]
    public void Same_password_produces_different_hashes()
    {
        // Har safar yangi salt — bir xil parol bir xil hash bermasligi kerak.
        Assert.NotEqual(_hasher.Hash("same password here"), _hasher.Hash("same password here"));
    }

    [Fact]
    public void Verify_returns_false_for_malformed_hash()
    {
        // Buzilgan yozuv istisno tashlamasligi kerak — shunchaki false.
        Assert.False(_hasher.Verify("any", "not-a-valid-hash", out _));
        Assert.False(_hasher.Verify("any", "", out _));
        Assert.False(_hasher.Verify("any", "v1$abc$def$ghi", out _));
    }

    [Fact]
    public void DummyHash_never_matches_but_is_parseable()
    {
        // Login'da foydalanuvchi topilmaganda ishlatiladi: format to'g'ri
        // bo'lishi kerak (aks holda Verify erta chiqib ketadi va vaqt farq qiladi).
        Assert.False(_hasher.Verify("anything at all", _hasher.DummyHash, out _));
        Assert.StartsWith("v1$", _hasher.DummyHash, StringComparison.Ordinal);
    }
}
