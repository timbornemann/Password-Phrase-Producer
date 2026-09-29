using System.Security.Cryptography;
using Password_Phrase_Producer.Services.Security;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class TotpKeyFileFormatTests
{
    [Fact]
    public void EncryptedKeyCanBeRecoveredWithoutSeparateMetadata()
    {
        var masterKey = RandomNumberGenerator.GetBytes(32);
        var file = TotpKeyFileFormat.Encrypt(masterKey, "correct password");

        Assert.True(TotpKeyFileFormat.IsV2(file));
        Assert.True(TotpKeyFileFormat.TryDecrypt(file, "correct password", out var recovered));
        Assert.Equal(masterKey, recovered);
        Assert.False(TotpKeyFileFormat.TryDecrypt(file, "wrong password", out _));
    }

    [Fact]
    public void CorruptedKeyFileIsRejected()
    {
        var file = TotpKeyFileFormat.Encrypt(RandomNumberGenerator.GetBytes(32), "password");
        file[^1] ^= 1;

        Assert.False(TotpKeyFileFormat.TryDecrypt(file, "password", out _));
        Assert.False(TotpKeyFileFormat.TryDecrypt(file[..^1], "password", out _));
    }
}
