using Password_Phrase_Producer.Services.Security;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class PasswordStrengthEstimatorTests
{
    [Fact]
    public void EmptyPasswordLeavesMeterEmpty()
        => Assert.Equal(0, PasswordStrengthEstimator.Estimate(string.Empty));

    [Fact]
    public void LongerDistinctPassphraseScoresHigherThanShortPassword()
        => Assert.True(PasswordStrengthEstimator.Estimate("correct horse battery staple") >
                       PasswordStrengthEstimator.Estimate("abc"));

    [Theory]
    [InlineData("password123456789")]
    [InlineData("123456123456123456")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void ObviousPatternsDoNotFillMeter(string password)
        => Assert.InRange(PasswordStrengthEstimator.Estimate(password), 0, 0.2);
}
