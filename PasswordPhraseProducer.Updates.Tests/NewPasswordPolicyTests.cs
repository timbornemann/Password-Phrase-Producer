using Password_Phrase_Producer.Services.Security;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class NewPasswordPolicyTests
{
    [Theory]
    [InlineData("short")]
    [InlineData("aaaaaaaaaaaaaaa")]
    [InlineData("password123456789")]
    [InlineData("123456789012345")]
    public void RejectsShortOrObviousNewPasswords(string password)
    {
        Assert.Throws<ArgumentException>(() => NewPasswordPolicy.Validate(password, nameof(password)));
    }

    [Fact]
    public void AcceptsLongPassphraseWithSpaces()
    {
        NewPasswordPolicy.Validate("Four distinct words make a passphrase", "password");
    }
}
