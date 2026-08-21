using AccessServer.Infrastructure.Security;
using Xunit;

namespace AccessServer.IntegrationTests;

public sealed class ApiTokenFactoryTests
{
    private readonly ApiTokenFactory _factory = new();

    [Fact]
    public void Created_token_starts_with_prefix_and_hashes_consistently()
    {
        var generated = _factory.Create();

        Assert.StartsWith("cc01_live_", generated.Prefix, StringComparison.Ordinal);
        Assert.StartsWith(generated.Prefix, generated.Secret, StringComparison.Ordinal);
        Assert.Equal(generated.Hash, _factory.ComputeHash(generated.Secret));
    }

    /// <summary>
    /// Regressiya: sir base64url alifbosida va uning ichida '_' uchraydi.
    /// `LastIndexOf('_')` bilan ajratish tokenlarning bir qismida noto'g'ri
    /// prefiks bergan va bazadan topilmay qolgan edi.
    /// Shuning uchun bitta emas, ko'p token tekshiriladi.
    /// </summary>
    [Fact]
    public void TryParsePrefix_roundtrips_even_when_secret_contains_underscore()
    {
        var withUnderscore = 0;

        for (var i = 0; i < 500; i++)
        {
            var generated = _factory.Create();

            Assert.True(_factory.TryParsePrefix(generated.Secret, out var prefix));
            Assert.Equal(generated.Prefix, prefix);

            // Sir qismida '_' bo'lgan holatlarni sanaymiz.
            if (generated.Secret[generated.Prefix.Length..].Contains('_', StringComparison.Ordinal))
            {
                withUnderscore++;
            }
        }

        // 500 ta tokenda '_' li sir deyarli albatta uchraydi; uchramasa test
        // aslida hech narsani tekshirmagan bo'lardi.
        Assert.True(withUnderscore > 0, "Sirida '_' bo'lgan token uchramadi — test ishonchsiz.");
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-token")]
    [InlineData("cc01_test_abc_def")]
    public void TryParsePrefix_rejects_foreign_tokens(string token) =>
        Assert.False(_factory.TryParsePrefix(token, out _));

    [Fact]
    public void Tokens_are_unique()
    {
        var secrets = Enumerable.Range(0, 200).Select(_ => _factory.Create().Secret).ToHashSet(StringComparer.Ordinal);
        Assert.Equal(200, secrets.Count);
    }
}
