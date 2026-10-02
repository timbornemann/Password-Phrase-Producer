using System.Security.Cryptography;
using System.Text;
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

    [Fact]
    public void VerifiesAcrossWindowsAndAndroidLineEndingsIncludingOlderWindowsBackups()
    {
        const string phrase = "backup password";
        var windowsOptions = new JsonSerializerOptions(Options) { NewLine = "\r\n" };
        var androidOptions = new JsonSerializerOptions(Options) { NewLine = "\n" };
        var backup = new FullBackupDto
        {
            PasswordVault = new PortableBackupDto { CipherText = "encrypted section" },
            DataVault = new PortableBackupDto { CipherText = "another section" }
        };

        FullBackupIntegrity.Seal(backup, phrase, windowsOptions);
        var payload = JsonSerializer.SerializeToUtf8Bytes(backup, windowsOptions);
        Assert.Contains("\r\n", Encoding.UTF8.GetString(payload));
        var onAndroid = JsonSerializer.Deserialize<FullBackupDto>(payload, androidOptions)!;
        FullBackupIntegrity.Verify(onAndroid, phrase, androidOptions);

        FullBackupIntegrity.Seal(backup, phrase, androidOptions);
        payload = JsonSerializer.SerializeToUtf8Bytes(backup, androidOptions);
        var onWindows = JsonSerializer.Deserialize<FullBackupDto>(payload, windowsOptions)!;
        FullBackupIntegrity.Verify(onWindows, phrase, windowsOptions);

        // Earlier Windows releases authenticated indented JSON with CRLF endings.
        backup.IntegrityMac = null;
        var key = Rfc2898DeriveBytes.Pbkdf2(phrase, Convert.FromBase64String(backup.IntegritySalt!),
            backup.IntegrityIterations!.Value, HashAlgorithmName.SHA256, 32);
        try
        {
            var oldMac = HMACSHA256.HashData(key, JsonSerializer.SerializeToUtf8Bytes(backup, windowsOptions));
            backup.IntegrityMac = Convert.ToBase64String(oldMac);
            CryptographicOperations.ZeroMemory(oldMac);
        }
        finally { CryptographicOperations.ZeroMemory(key); }

        payload = JsonSerializer.SerializeToUtf8Bytes(backup, windowsOptions);
        onAndroid = JsonSerializer.Deserialize<FullBackupDto>(payload, androidOptions)!;
        FullBackupIntegrity.Verify(onAndroid, phrase, androidOptions);
        onAndroid.DataVault!.CipherText = "changed";
        Assert.Throws<InvalidDataException>(() => FullBackupIntegrity.Verify(onAndroid, phrase, androidOptions));
    }
}
