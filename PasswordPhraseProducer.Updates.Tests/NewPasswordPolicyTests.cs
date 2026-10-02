using Password_Phrase_Producer.Services.Security;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class NewPasswordPolicyTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void RejectsMissingNewPasswords(string? password)
    {
        Assert.Throws<ArgumentException>(() => NewPasswordPolicy.Validate(password, nameof(password)));
    }

    [Theory]
    [InlineData("a")]
    [InlineData("short")]
    [InlineData("aaaaaaaaaaaaaaa")]
    [InlineData("password123456789")]
    [InlineData("123456789012345")]
    [InlineData("Four distinct words make a passphrase")]
    [InlineData("!@#")]
    public void AcceptsAnyNonBlankNewPassword(string password)
    {
        NewPasswordPolicy.Validate(password, nameof(password));
    }
}
