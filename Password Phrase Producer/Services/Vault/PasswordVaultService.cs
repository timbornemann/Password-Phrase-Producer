using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Services.Vault;

public static class VaultMessages
{
    public const string EntriesChanged = nameof(EntriesChanged);
}

public class PasswordVaultService
{
    private const string VaultFileName = "vault.json.enc";
    private const string PasswordSaltStorageKey = "PasswordVaultMasterPasswordSalt";
    private const string PasswordVerifierStorageKey = "PasswordVaultMasterPasswordVerifier";
    private const string BiometricKeyStorageKey = "PasswordVaultBiometricKey";
    private const int KeySizeBytes = 32;
    private const int SaltSizeBytes = 16;
    private const int Pbkdf2Iterations = 200_000;

    private readonly SemaphoreSlim _syncLock = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private readonly string _vaultFilePath;
    private byte[]? _encryptionKey;

    public PasswordVaultService()
    {
        _vaultFilePath = Path.Combine(FileSystem.AppDataDirectory, VaultFileName);
    }

    public bool IsUnlocked => _encryptionKey is not null;

    public async Task<bool> HasMasterPasswordAsync(CancellationToken cancellationToken = default)
    {
        var salt = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey).ConfigureAwait(false);
        return !string.IsNullOrEmpty(salt);
    }

    public async Task<bool> HasBiometricKeyAsync(CancellationToken cancellationToken = default)
    {
        var stored = await SecureStorage.Default.GetAsync(BiometricKeyStorageKey).ConfigureAwait(false);
        return !string.IsNullOrEmpty(stored);
    }

    public void Lock()
    {
        if (_encryptionKey is null)
        {
            return;
        }

        Array.Clear(_encryptionKey);
        _encryptionKey = null;
    }

    public async Task SetMasterPasswordAsync(string password, bool enableBiometrics, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        var key = DeriveKey(password, salt);
        var verifier = CreateVerifier(key);

        await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, Convert.ToBase64String(salt)).ConfigureAwait(false);
        await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, Convert.ToBase64String(verifier)).ConfigureAwait(false);

        _encryptionKey = key;

        if (enableBiometrics)
        {
            await SecureStorage.Default.SetAsync(BiometricKeyStorageKey, Convert.ToBase64String(key)).ConfigureAwait(false);
        }
        else
        {
            SecureStorage.Default.Remove(BiometricKeyStorageKey);
        }
    }

    public async Task<bool> UnlockAsync(string password, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var saltBase64 = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey).ConfigureAwait(false);
        var verifierBase64 = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey).ConfigureAwait(false);

        if (string.IsNullOrEmpty(saltBase64) || string.IsNullOrEmpty(verifierBase64))
        {
            return false;
        }

        var salt = Convert.FromBase64String(saltBase64);
        var key = DeriveKey(password, salt);
        var expectedVerifier = Convert.FromBase64String(verifierBase64);
        var actualVerifier = CreateVerifier(key);

        if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
        {
            Array.Clear(key);
            return false;
        }

        _encryptionKey = key;
        return true;
    }

    public async Task ChangeMasterPasswordAsync(string newPassword, bool enableBiometrics, CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();
        ArgumentException.ThrowIfNullOrWhiteSpace(newPassword);

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);

            var newSalt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
            var newKey = DeriveKey(newPassword, newSalt);
            var newVerifier = CreateVerifier(newKey);

            var previousKey = _encryptionKey;
            _encryptionKey = newKey;

            try
            {
                await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                _encryptionKey = previousKey;
                Array.Clear(newKey);
                throw;
            }

            await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, Convert.ToBase64String(newSalt)).ConfigureAwait(false);
            await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, Convert.ToBase64String(newVerifier)).ConfigureAwait(false);

            if (enableBiometrics)
            {
                await SecureStorage.Default.SetAsync(BiometricKeyStorageKey, Convert.ToBase64String(newKey)).ConfigureAwait(false);
            }
            else
            {
                SecureStorage.Default.Remove(BiometricKeyStorageKey);
            }

            if (previousKey is not null)
            {
                Array.Clear(previousKey);
            }
        }
        finally
        {
            _syncLock.Release();
        }
    }

    public async Task<bool> TryUnlockWithStoredKeyAsync(CancellationToken cancellationToken = default)
    {
        var storedKeyBase64 = await SecureStorage.Default.GetAsync(BiometricKeyStorageKey).ConfigureAwait(false);
        var verifierBase64 = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey).ConfigureAwait(false);

        if (string.IsNullOrEmpty(storedKeyBase64) || string.IsNullOrEmpty(verifierBase64))
        {
            return false;
        }

        var key = Convert.FromBase64String(storedKeyBase64);
        var expectedVerifier = Convert.FromBase64String(verifierBase64);
        var actualVerifier = CreateVerifier(key);

        if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
        {
            SecureStorage.Default.Remove(BiometricKeyStorageKey);
            Array.Clear(key);
            return false;
        }

        _encryptionKey = key;
        return true;
    }

    public async Task SetBiometricUnlockAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        if (!IsUnlocked)
        {
            throw new InvalidOperationException("Der Tresor ist gesperrt.");
        }

        if (enabled)
        {
            await SecureStorage.Default.SetAsync(BiometricKeyStorageKey, Convert.ToBase64String(_encryptionKey!)).ConfigureAwait(false);
        }
        else
        {
            SecureStorage.Default.Remove(BiometricKeyStorageKey);
        }
    }

    public async Task<IReadOnlyList<PasswordVaultEntry>> GetEntriesAsync(CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            return entries
                .OrderBy(e => e.DisplayCategory, StringComparer.CurrentCultureIgnoreCase)
                .ThenBy(e => e.Label, StringComparer.CurrentCultureIgnoreCase)
                .ToList();
        }
        finally
        {
            _syncLock.Release();
        }
    }

    public async Task AddOrUpdateEntryAsync(PasswordVaultEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            var existingIndex = entries.FindIndex(e => e.Id == entry.Id);

            if (entry.Id == Guid.Empty)
            {
                entry.Id = Guid.NewGuid();
            }

            entry.ModifiedAt = DateTimeOffset.UtcNow;

            if (existingIndex >= 0)
            {
                entries[existingIndex] = entry.Clone();
            }
            else
            {
                entries.Add(entry.Clone());
            }

            await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }

        MessagingCenter.Send(this, VaultMessages.EntriesChanged);
    }

    public async Task DeleteEntryAsync(Guid entryId, CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            var removed = entries.RemoveAll(e => e.Id == entryId);

            if (removed > 0)
            {
                await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _syncLock.Release();
        }

        MessagingCenter.Send(this, VaultMessages.EntriesChanged);
    }

    public async Task<byte[]> CreateBackupAsync(CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var encryptedPayload = await ReadEncryptedFileAsync(cancellationToken).ConfigureAwait(false);
            var salt = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey).ConfigureAwait(false)
                       ?? throw new InvalidOperationException("Kein Master-Passwort konfiguriert.");
            var verifier = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey).ConfigureAwait(false)
                          ?? throw new InvalidOperationException("Kein Master-Passwort konfiguriert.");

            var backup = new PasswordVaultBackupDto
            {
                CipherText = Convert.ToBase64String(encryptedPayload),
                PasswordSalt = salt,
                PasswordVerifier = verifier,
                Pbkdf2Iterations = Pbkdf2Iterations,
                CreatedAt = DateTimeOffset.UtcNow
            };

            var json = JsonSerializer.Serialize(backup, _jsonOptions);
            return Encoding.UTF8.GetBytes(json);
        }
        finally
        {
            _syncLock.Release();
        }
    }

    public async Task RestoreBackupAsync(Stream backupStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(backupStream);

        using var reader = new StreamReader(backupStream, Encoding.UTF8, leaveOpen: true);
        var json = await reader.ReadToEndAsync().ConfigureAwait(false);
        var dto = JsonSerializer.Deserialize<PasswordVaultBackupDto>(json, _jsonOptions)
                  ?? throw new InvalidOperationException("Ungültiges Backup-Format.");

        var cipher = Convert.FromBase64String(dto.CipherText);

        if (dto.Pbkdf2Iterations != Pbkdf2Iterations)
        {
            throw new InvalidOperationException("Das Backup wurde mit einer nicht unterstützten Schlüsselableitung erstellt.");
        }

        await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, dto.PasswordSalt).ConfigureAwait(false);
        await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, dto.PasswordVerifier).ConfigureAwait(false);
        SecureStorage.Default.Remove(BiometricKeyStorageKey);
        _encryptionKey = null;

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_vaultFilePath)!);
            await File.WriteAllBytesAsync(_vaultFilePath, cipher, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }

        MessagingCenter.Send(this, VaultMessages.EntriesChanged);
    }

    public async Task<byte[]> ExportEncryptedVaultAsync(CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ReadEncryptedFileAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }
    }

    public async Task ImportEncryptedVaultAsync(Stream encryptedStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptedStream);
        EnsureUnlocked();

        using var memoryStream = new MemoryStream();
        await encryptedStream.CopyToAsync(memoryStream, cancellationToken).ConfigureAwait(false);
        var payload = memoryStream.ToArray();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_vaultFilePath)!);
            await File.WriteAllBytesAsync(_vaultFilePath, payload, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }

        MessagingCenter.Send(this, VaultMessages.EntriesChanged);
    }

    private async Task<List<PasswordVaultEntry>> LoadEntriesInternalAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_vaultFilePath))
        {
            return new List<PasswordVaultEntry>();
        }

        var encrypted = await File.ReadAllBytesAsync(_vaultFilePath, cancellationToken).ConfigureAwait(false);
        if (encrypted.Length == 0)
        {
            return new List<PasswordVaultEntry>();
        }

        var decryptedBytes = await DecryptAsync(encrypted, cancellationToken).ConfigureAwait(false);
        if (decryptedBytes.Length == 0)
        {
            return new List<PasswordVaultEntry>();
        }

        var json = Encoding.UTF8.GetString(decryptedBytes);
        var snapshot = JsonSerializer.Deserialize<PasswordVaultSnapshotDto>(json, _jsonOptions);

        if (snapshot?.Entries is null)
        {
            return new List<PasswordVaultEntry>();
        }

        return snapshot.Entries
            .Select(dto => dto.ToModel())
            .ToList();
    }

    private async Task SaveEntriesInternalAsync(IList<PasswordVaultEntry> entries, CancellationToken cancellationToken)
    {
        var ordered = entries
            .OrderBy(e => e.DisplayCategory, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(e => e.Label, StringComparer.CurrentCultureIgnoreCase)
            .Select(PasswordVaultEntryDto.FromModel)
            .ToList();

        var snapshot = new PasswordVaultSnapshotDto
        {
            Entries = ordered,
            ExportedAt = DateTimeOffset.UtcNow
        };

        var json = JsonSerializer.Serialize(snapshot, _jsonOptions);
        var encrypted = await EncryptAsync(Encoding.UTF8.GetBytes(json), cancellationToken).ConfigureAwait(false);

        Directory.CreateDirectory(Path.GetDirectoryName(_vaultFilePath)!);
        await File.WriteAllBytesAsync(_vaultFilePath, encrypted, cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken)
    {
        var key = GetUnlockedKey();
        var nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[data.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(nonce, data, cipher, tag);

        var result = new byte[nonce.Length + cipher.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(cipher, 0, result, nonce.Length, cipher.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + cipher.Length, tag.Length);
        return result;
    }

    private async Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken)
    {
        if (data.Length < 28)
        {
            return Array.Empty<byte>();
        }

        var key = GetUnlockedKey();

        var nonce = new byte[12];
        var tag = new byte[16];
        var cipher = new byte[data.Length - 28];

        Buffer.BlockCopy(data, 0, nonce, 0, nonce.Length);
        Buffer.BlockCopy(data, nonce.Length, cipher, 0, cipher.Length);
        Buffer.BlockCopy(data, nonce.Length + cipher.Length, tag, 0, tag.Length);

        var plain = new byte[cipher.Length];

        using var aes = new AesGcm(key, tag.Length);
        aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    private async Task<byte[]> ReadEncryptedFileAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_vaultFilePath))
        {
            return Array.Empty<byte>();
        }

        return await File.ReadAllBytesAsync(_vaultFilePath, cancellationToken).ConfigureAwait(false);
    }

    private byte[] GetUnlockedKey()
    {
        if (_encryptionKey is null)
        {
            throw new InvalidOperationException("Der Tresor ist gesperrt.");
        }

        return _encryptionKey;
    }

    private void EnsureUnlocked()
    {
        if (!IsUnlocked)
        {
            throw new InvalidOperationException("Der Tresor ist gesperrt.");
        }
    }

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(KeySizeBytes);
    }

    private static byte[] CreateVerifier(byte[] key)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(key);
    }
}
