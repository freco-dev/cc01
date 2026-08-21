using AccessServer.Application.Validation;
using Xunit;

namespace AccessServer.IntegrationTests;

/// <summary>
/// DEV_SPEC §6.6: bu qoidalar Go tomonda ham bir xil bo'lishi shart.
/// Shu jadval keyinchalik test/contract uchun asos bo'ladi — Go
/// implementatsiyasi aynan shu kirishlarda bir xil natija berishi kerak.
/// </summary>
public sealed class SubdomainRulesTests
{
    [Theory]
    // to'g'ri
    [InlineData("myapp", SubdomainValidation.Ok)]
    [InlineData("abc", SubdomainValidation.Ok)]
    [InlineData("a1-b2", SubdomainValidation.Ok)]
    [InlineData("1abc", SubdomainValidation.Ok)]
    [InlineData("a-b-c-d", SubdomainValidation.Ok)]
    // uzunlik
    [InlineData("ab", SubdomainValidation.BadLength)]
    [InlineData("", SubdomainValidation.Empty)]
    // format
    [InlineData("-abc", SubdomainValidation.BadFormat)]
    [InlineData("abc-", SubdomainValidation.BadFormat)]
    [InlineData("a--b", SubdomainValidation.BadFormat)]
    [InlineData("MyApp", SubdomainValidation.BadFormat)]
    [InlineData("a_b", SubdomainValidation.BadFormat)]
    [InlineData("a.b", SubdomainValidation.BadFormat)]
    [InlineData("ab c", SubdomainValidation.BadFormat)]
    // deny-list
    [InlineData("www", SubdomainValidation.Reserved)]
    [InlineData("api", SubdomainValidation.Reserved)]
    [InlineData("admin", SubdomainValidation.Reserved)]
    public void Validate_returns_expected(string candidate, SubdomainValidation expected) =>
        Assert.Equal(expected, SubdomainRules.Validate(candidate));

    [Fact]
    public void Length_boundaries_are_inclusive()
    {
        Assert.Equal(SubdomainValidation.Ok,
            SubdomainRules.Validate(new string('a', SubdomainRules.MinLength)));

        Assert.Equal(SubdomainValidation.Ok,
            SubdomainRules.Validate(new string('a', SubdomainRules.MaxLength)));

        Assert.Equal(SubdomainValidation.BadLength,
            SubdomainRules.Validate(new string('a', SubdomainRules.MaxLength + 1)));
    }
}
