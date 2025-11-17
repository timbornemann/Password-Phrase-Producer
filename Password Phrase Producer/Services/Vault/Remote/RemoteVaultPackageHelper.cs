using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Services.Vault;

internal static class RemoteVaultPackageHelper
{
    private const int CurrentPackageVersion = 1;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    public static byte[] CreatePackage(
        RemoteVaultSnapshotDto snapshot,
        string password,
        int iterations,
        int saltSizeBytes,
        int keySizeBytes,
        JsonSerializerOptions options,
        byte[]? saltOverride = null)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ArgumentNullException.ThrowIfNull(options);

        var json = JsonSerializer.Serialize(snapshot, options);
        var data = Encoding.UTF8.GetBytes(json);
        var salt = saltOverride ?? RandomNumberGenerator.GetBytes(saltSizeBytes);
        var key = DeriveKey(password, salt, iterations, keySizeBytes);

        try
        {
            var encrypted = EncryptWithKey(data, key);
            var dto = new RemoteVaultPackageDto
            {
                Version = CurrentPackageVersion,
                Salt = Convert.ToBase64String(salt),
                Pbkdf2Iterations = iterations,
                CipherText = Convert.ToBase64String(encrypted)
            };

            return JsonSerializer.SerializeToUtf8Bytes(dto, options);
        }
        finally
        {
            Array.Clear(key);
            Array.Clear(data);
            if (saltOverride is null)
            {
                Array.Clear(salt);
            }
        }
    }

    public static RemoteVaultSnapshotDto DecryptPackage(
        byte[] packageBytes,
        string password,
        int defaultIterations,
        int keySizeBytes,
        JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(packageBytes);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ArgumentNullException.ThrowIfNull(options);

        var package = ParseRemotePackage(packageBytes, options);
        if (string.IsNullOrWhiteSpace(package.CipherText))
        {
            return new RemoteVaultSnapshotDto();
        }

        if (string.IsNullOrWhiteSpace(package.Salt))
        {
            throw new InvalidOperationException("Das Remote-Tresorformat enthält keine Salt-Informationen.");
        }

        var salt = Convert.FromBase64String(package.Salt);
        var encrypted = Convert.FromBase64String(package.CipherText);
        var iterations = package.Pbkdf2Iterations.HasValue && package.Pbkdf2Iterations.Value > 0
            ? package.Pbkdf2Iterations.Value
            : defaultIterations;
        var key = DeriveKey(password, salt, iterations, keySizeBytes);
        byte[]? plain = null;

        try
        {
            plain = DecryptWithKey(encrypted, key);
            var snapshot = JsonSerializer.Deserialize<RemoteVaultSnapshotDto>(plain, options);
            if (snapshot is null)
            {
                throw new InvalidOperationException("Der Remote-Snapshot konnte nicht gelesen werden.");
            }

            snapshot.Entries ??= new List<PasswordVaultEntryDto>();
            return snapshot;
        }
        catch (JsonException ex)
        {
            if (plain is not null && LooksLikeLegacyRemoteVaultContent(plain))
            {
                throw new LegacyRemoteVaultFormatException("Die entfernte Datei verwendet ein älteres Tresorformat und kann nicht automatisch importiert werden. Bitte importiere die Datei lokal und exportiere sie anschließend erneut.", ex);
            }

            throw new InvalidOperationException("Der Remote-Snapshot ist beschädigt oder hat ein unbekanntes Format.", ex);
        }
        finally
        {
            if (plain is not null)
            {
                Array.Clear(plain);
            }

            Array.Clear(key);
        }
    }

    private static RemoteVaultPackageDto ParseRemotePackage(byte[] payload, JsonSerializerOptions options)
    {
        try
        {
            var dto = JsonSerializer.Deserialize<RemoteVaultPackageDto>(payload, options);
            if (dto is null || string.IsNullOrWhiteSpace(dto.CipherText))
            {
                throw new InvalidOperationException("Das Remote-Tresorformat ist ungültig.");
            }

            if (dto.Version != CurrentPackageVersion)
            {
                throw new InvalidOperationException("Das Remote-Tresorformat wird nicht unterstützt.");
            }

            return dto;
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("Die entfernten Tresordaten konnten nicht interpretiert werden.", ex);
        }
    }

    private static bool LooksLikeLegacyRemoteVaultContent(ReadOnlySpan<byte> plain)
    {
        try
        {
            using var document = JsonDocument.Parse(plain);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            return root.TryGetProperty("passwordSalt", out _) && root.TryGetProperty("passwordVerifier", out _);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations, int keySizeBytes)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(keySizeBytes);
    }

    private static byte[] EncryptWithKey(byte[] data, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var cipher = new byte[data.Length];
        var tag = new byte[TagSizeBytes];

        using var aes = new AesGcm(key, TagSizeBytes);
        aes.Encrypt(nonce, data, cipher, tag);

        var result = new byte[nonce.Length + cipher.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(cipher, 0, result, nonce.Length, cipher.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + cipher.Length, tag.Length);
        return result;
    }

    private static byte[] DecryptWithKey(byte[] data, byte[] key)
    {
        if (data.Length < NonceSizeBytes + TagSizeBytes)
        {
            return Array.Empty<byte>();
        }

        var cipherLength = data.Length - NonceSizeBytes - TagSizeBytes;
        var nonce = new byte[NonceSizeBytes];
        var cipher = new byte[cipherLength];
        var tag = new byte[TagSizeBytes];

        Buffer.BlockCopy(data, 0, nonce, 0, NonceSizeBytes);
        Buffer.BlockCopy(data, NonceSizeBytes, cipher, 0, cipherLength);
        Buffer.BlockCopy(data, NonceSizeBytes + cipherLength, tag, 0, TagSizeBytes);

        var plain = new byte[cipherLength];
        using var aes = new AesGcm(key, TagSizeBytes);
        aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    private sealed record RemoteVaultPackageDto
    {
        public int Version { get; init; }
        public string? Salt { get; init; }
        public int? Pbkdf2Iterations { get; init; }
        public string CipherText { get; init; } = string.Empty;
    }
}

internal sealed class LegacyRemoteVaultFormatException : InvalidOperationException
{
    public LegacyRemoteVaultFormatException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
