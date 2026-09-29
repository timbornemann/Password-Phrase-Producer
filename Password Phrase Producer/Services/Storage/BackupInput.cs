using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Services.Storage;

internal static class BackupInput
{
    internal const int MaxBytes = 128 * 1024 * 1024;

    internal static async Task<string> ReadJsonAsync(Stream stream, CancellationToken cancellationToken = default,
        int maxBytes = MaxBytes)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        int count;
        while ((count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
        {
            if (output.Length + count > maxBytes)
                throw new InvalidDataException("Die Sicherungsdatei ist zu groß.");
            output.Write(buffer, 0, count);
        }

        var bytes = output.GetBuffer().AsSpan(0, checked((int)output.Length));
        if (bytes.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) bytes = bytes[3..];
        return new UTF8Encoding(false, true).GetString(bytes);
    }

    internal static (byte[] Salt, byte[] Verifier, byte[] Cipher) Validate(PortableBackupDto backup)
    {
        ArgumentNullException.ThrowIfNull(backup);
        if (backup.Iterations is < 10_000 or > 1_000_000)
            throw new InvalidDataException("Ungültige Schlüsselableitung in der Sicherungsdatei.");
        try
        {
            var salt = Convert.FromBase64String(backup.Salt);
            var verifier = Convert.FromBase64String(backup.Verifier);
            var cipher = Convert.FromBase64String(backup.CipherText);
            if (salt.Length != 16 || verifier.Length != 32 || cipher.Length < 28)
                throw new InvalidDataException("Ungültige Verschlüsselungsdaten in der Sicherungsdatei.");
            return (salt, verifier, cipher);
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("Ungültiges Base64 in der Sicherungsdatei.", ex);
        }
    }

    internal static void VerifyDecryptable(PortableBackupDto backup, string password, Action<byte[]>? validateSnapshot = null)
    {
        var validated = Validate(backup);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, validated.Salt, backup.Iterations,
            HashAlgorithmName.SHA256, 32);
        byte[]? plaintext = null;
        try
        {
            var actualVerifier = SHA256.HashData(key);
            if (!CryptographicOperations.FixedTimeEquals(validated.Verifier, actualVerifier))
                throw new InvalidDataException("Falsches Datei-Passwort.");

            var cipherLength = validated.Cipher.Length - 28;
            plaintext = new byte[cipherLength];
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(validated.Cipher.AsSpan(0, 12), validated.Cipher.AsSpan(12, cipherLength),
                validated.Cipher.AsSpan(12 + cipherLength, 16), plaintext);
            using var document = JsonDocument.Parse(plaintext);
            if (!document.RootElement.TryGetProperty("entries", out var entries) ||
                entries.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("Die Sicherungsdatei enthält keinen gültigen Snapshot.");
            validateSnapshot?.Invoke(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(validated.Cipher);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
