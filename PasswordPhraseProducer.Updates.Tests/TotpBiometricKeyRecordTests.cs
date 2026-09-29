using System.Security.Cryptography;
using Password_Phrase_Producer.Services.Security;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class TotpBiometricKeyRecordTests
{
    [Fact]
    public void WrapperIsBoundToMasterKeyAndCurrentKeyFile()
    {
        var masterKey = RandomNumberGenerator.GetBytes(32);
        var oldKeyFile = RandomNumberGenerator.GetBytes(117);
        var record = TotpBiometricKeyRecord.Create(RandomNumberGenerator.GetBytes(48), oldKeyFile, masterKey);

        Assert.True(TotpBiometricKeyRecord.TryParse(record.Serialize(), out var restored));
        Assert.NotNull(restored);
        Assert.True(restored.MatchesKeyFile(oldKeyFile));
        Assert.True(restored.MatchesMasterKey(masterKey));
        Assert.False(restored.MatchesKeyFile(RandomNumberGenerator.GetBytes(117)));
        Assert.False(restored.MatchesMasterKey(RandomNumberGenerator.GetBytes(32)));

        var changedPasswordFile = RandomNumberGenerator.GetBytes(117);
        restored.RebindKeyFile(changedPasswordFile);
        Assert.True(restored.MatchesKeyFile(changedPasswordFile));
        Assert.False(restored.MatchesKeyFile(oldKeyFile));
        Assert.True(restored.MatchesMasterKey(masterKey));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"Version\":2}")]
    [InlineData("{\"Version\":1,\"EncryptedKey\":\"!\",\"KeyFileHash\":\"!\",\"MasterKeyHash\":\"!\"}")]
    public void InvalidOrTamperedRecordIsRejected(string json)
    {
        Assert.False(TotpBiometricKeyRecord.TryParse(json, out _));
    }
}
