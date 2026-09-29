using Password_Phrase_Producer.Services.Security;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class BiometricAuthenticationServiceTests
{
    [Fact]
    public async Task UnsupportedPlatformNeverReturnsUnprotectedKeyMaterial()
    {
        var service = new BiometricAuthenticationService();
        var secret = new byte[] { 1, 2, 3, 4 };

        Assert.False(await service.IsAvailableAsync());
        Assert.False(await service.AuthenticateAsync("unlock"));
        await Assert.ThrowsAsync<NotSupportedException>(() => service.EncryptAsync(secret));
        await Assert.ThrowsAsync<NotSupportedException>(() => service.DecryptAsync(secret));
    }
}
