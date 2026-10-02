using System.Security.Cryptography;
using System.Text.Json;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Services.Storage;

internal static class FullBackupIntegrity
{
    private const int Iterations = 600_000;
    private const int SaltLength = 16;
    private const int KeyLength = 32;
    // Indented System.Text.Json output otherwise uses the platform's line ending.
    private const string CanonicalNewLine = "\n";
    private const string LegacyWindowsNewLine = "\r\n";

    internal static void Seal(FullBackupDto backup, string password, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(backup);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        RequireContents(backup);
        backup.Version = 3;
        backup.IntegritySalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(SaltLength));
        backup.IntegrityIterations = Iterations;
        backup.IntegrityMac = null;
        var key = DeriveKey(backup, password);
        try
        {
            var mac = ComputeMac(backup, key, options, CanonicalNewLine);
            try { backup.IntegrityMac = Convert.ToBase64String(mac); }
            finally { CryptographicOperations.ZeroMemory(mac); }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal static void Verify(FullBackupDto backup, string password, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(backup);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        RequireContents(backup);
        if (backup.Version != 3 || backup.IntegrityIterations is < 10_000 or > 1_000_000 ||
            string.IsNullOrWhiteSpace(backup.IntegritySalt) || string.IsNullOrWhiteSpace(backup.IntegrityMac))
            throw new InvalidDataException("Die Integritätsdaten des Gesamtbackups fehlen oder sind ungültig.");

        byte[] expected;
        try { expected = Convert.FromBase64String(backup.IntegrityMac); }
        catch (FormatException ex) { throw new InvalidDataException("Ungültige Backup-Prüfsumme.", ex); }
        if (expected.Length != KeyLength)
        {
            CryptographicOperations.ZeroMemory(expected);
            throw new InvalidDataException("Ungültige Backup-Prüfsumme.");
        }

        byte[] key;
        try { key = DeriveKey(backup, password); }
        catch
        {
            CryptographicOperations.ZeroMemory(expected);
            throw;
        }
        try
        {
            foreach (var newLine in new[] { CanonicalNewLine, LegacyWindowsNewLine })
            {
                var actual = ComputeMac(backup, key, options, newLine);
                try
                {
                    if (CryptographicOperations.FixedTimeEquals(expected, actual)) return;
                }
                finally { CryptographicOperations.ZeroMemory(actual); }
            }
            throw new InvalidDataException("Das Gesamtbackup wurde verändert oder das Datei-Passwort ist falsch.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static void RequireContents(FullBackupDto backup)
    {
#pragma warning disable CS0618 // Detect and reject the legacy plaintext authenticator section.
        if (backup.Authenticator is not null ||
            backup.PasswordVault is null && backup.DataVault is null && backup.AuthenticatorEncrypted is null)
#pragma warning restore CS0618
            throw new InvalidDataException("Das Gesamtbackup enthält keine gültigen verschlüsselten Tresore.");
    }

    private static byte[] DeriveKey(FullBackupDto backup, string password)
    {
        byte[] salt;
        try { salt = Convert.FromBase64String(backup.IntegritySalt!); }
        catch (FormatException ex) { throw new InvalidDataException("Ungültiges Backup-Salt.", ex); }
        try
        {
            if (salt.Length != SaltLength || backup.IntegrityIterations is not { } iterations ||
                iterations is < 10_000 or > 1_000_000)
                throw new InvalidDataException("Ungültige Schlüsselableitung im Gesamtbackup.");
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, KeyLength);
        }
        finally { CryptographicOperations.ZeroMemory(salt); }
    }

    private static byte[] ComputeMac(FullBackupDto backup, byte[] key, JsonSerializerOptions options,
        string newLine)
    {
        var previousMac = backup.IntegrityMac;
        byte[]? bytes = null;
        try
        {
            backup.IntegrityMac = null;
            var stableOptions = new JsonSerializerOptions(options) { NewLine = newLine };
            bytes = JsonSerializer.SerializeToUtf8Bytes(backup, stableOptions);
            return HMACSHA256.HashData(key, bytes);
        }
        finally
        {
            backup.IntegrityMac = previousMac;
            if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
