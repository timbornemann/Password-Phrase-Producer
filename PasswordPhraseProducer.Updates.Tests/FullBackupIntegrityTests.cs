using System.Text.Json;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Storage;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class FullBackupIntegrityTests
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    [Fact]
    public void RejectsRemovedOrSwappedVaultSections()
    {
        var backup = new FullBackupDto
        {
            PasswordVault = new PortableBackupDto { CipherText = "one" },
            DataVault = new PortableBackupDto { CipherText = "two" }
        };
        FullBackupIntegrity.Seal(backup, "backup password", Options);
        FullBackupIntegrity.Verify(backup, "backup password", Options);

        var changed = JsonSerializer.Deserialize<FullBackupDto>(JsonSerializer.Serialize(backup, Options), Options)!;
        changed.DataVault = null;
        Assert.Throws<InvalidDataException>(() => FullBackupIntegrity.Verify(changed, "backup password", Options));

        changed.DataVault = new PortableBackupDto { CipherText = "other" };
        Assert.Throws<InvalidDataException>(() => FullBackupIntegrity.Verify(changed, "backup password", Options));
        Assert.Throws<InvalidDataException>(() => FullBackupIntegrity.Verify(backup, "wrong password", Options));
    }

    [Fact]
    public void RejectsEmptyBackupAndUnboundedKdf()
    {
        Assert.Throws<InvalidDataException>(() => FullBackupIntegrity.Seal(new FullBackupDto(), "password", Options));
        var backup = new FullBackupDto { PasswordVault = new PortableBackupDto() };
        FullBackupIntegrity.Seal(backup, "password", Options);
        backup.IntegrityIterations = int.MaxValue;
        Assert.Throws<InvalidDataException>(() => FullBackupIntegrity.Verify(backup, "password", Options));
    }
}
