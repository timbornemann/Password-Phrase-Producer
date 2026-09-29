using System.Security.Cryptography;
using System.Text;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Storage;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class BackupInputTests
{
    [Fact]
    public async Task RejectsOversizedBackupBeforeParsing()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("{\"too\":\"large\"}"));
        await Assert.ThrowsAsync<InvalidDataException>(() => BackupInput.ReadJsonAsync(stream, maxBytes: 8));
    }

    [Fact]
    public void RejectsUnboundedKdfWorkBeforeDerivation()
    {
        var backup = new PortableBackupDto { Iterations = int.MaxValue };
        Assert.Throws<InvalidDataException>(() => BackupInput.VerifyDecryptable(backup, "password"));
    }

    [Fact]
    public void PreflightVerifiesPasswordCipherAndSnapshot()
    {
        const string password = "backup password";
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, 200_000, HashAlgorithmName.SHA256, 32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = Encoding.UTF8.GetBytes("{\"entries\":[]}");
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plaintext, cipher, tag);
        var backup = new PortableBackupDto
        {
            Salt = Convert.ToBase64String(salt),
            Verifier = Convert.ToBase64String(SHA256.HashData(key)),
            Iterations = 200_000,
            CipherText = Convert.ToBase64String(nonce.Concat(cipher).Concat(tag).ToArray())
        };

        BackupInput.VerifyDecryptable(backup, password);
        Assert.Throws<InvalidDataException>(() => BackupInput.VerifyDecryptable(backup, "wrong password"));
        backup.CipherText = Convert.ToBase64String(nonce.Concat(cipher).Concat(new byte[16]).ToArray());
        Assert.ThrowsAny<CryptographicException>(() => BackupInput.VerifyDecryptable(backup, password));
    }
}
