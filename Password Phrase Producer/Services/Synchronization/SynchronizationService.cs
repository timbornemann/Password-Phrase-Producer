using PasswordPhraseProducer.Updates;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Vault;
using Password_Phrase_Producer.Services.Storage;
using static Password_Phrase_Producer.Models.SyncModels;

namespace Password_Phrase_Producer.Services.Synchronization;

public interface ISynchronizationService
{
    Task<bool> IsConfiguredAsync();
    Task<bool> HasConfigurationAsync();
    Task ConfigureAsync(string path, string password);
    Task<bool> ValidatePasswordAsync(string password); // Checks if password matches existing file
    Task<SyncAccessMode> GetAccessModeAsync();
    Task SetAccessModeAsync(SyncAccessMode mode);
    Task ClearConfigurationAsync();
    Task SyncPasswordVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default);
    Task SyncDataVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default);
    Task SyncAuthenticatorAsync(IList<TotpEntry> localEntries, CancellationToken cancellationToken = default);
    Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedPasswordVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default);
    Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedDataVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default);
    Task<Services.Vault.MergeResult<TotpEntry>> GetMergedAuthenticatorAsync(IList<TotpEntry> localEntries, CancellationToken cancellationToken = default);
    Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedPasswordVaultReadOnlyAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default);
    Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedDataVaultReadOnlyAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default);
    Task<Services.Vault.MergeResult<TotpEntry>> GetMergedAuthenticatorReadOnlyAsync(IList<TotpEntry> localEntries, CancellationToken cancellationToken = default);
}

public enum SyncAccessMode
{
    ReadWrite = 0,
    ReadMerge = 1
}

public class SynchronizationService : ISynchronizationService
{
    private const string SyncPathKey = "SyncFilePath";
    private const string SyncKeyStorageKey = "SyncCommonKey_Encrypted";
    private const string SyncAccessModeKey = "SyncAccessMode";
    private const int KeySize = 32;
    private const int SaltSize = 16;
    private const int Iterations = 600_000;

    private readonly ISyncFileService _syncFileService;
    private readonly IAppLockService _appLockService;
    private readonly VaultMergeService _vaultMergeService;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public SynchronizationService(IAppLockService appLockService, VaultMergeService vaultMergeService, ISyncFileService syncFileService)
    {
        _appLockService = appLockService;
        _vaultMergeService = vaultMergeService;
        _syncFileService = syncFileService;
    }

    public async Task ConfigureAsync(string path, string password)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Path and password are required.");
            if (!_appLockService.IsUnlocked)
                throw new InvalidOperationException("App must be unlocked to configure sync.");

            await _fileLock.WaitAsync().ConfigureAwait(false);
            try
            {
                var exists = await _syncFileService.ExistsAsync(path).ConfigureAwait(false);
                var hasContent = false;
                if (exists)
                {
                    using var stream = await _syncFileService.OpenReadAsync(path).ConfigureAwait(false);
                    hasContent = await stream.ReadAsync(new byte[1]).ConfigureAwait(false) > 0;
                }

                byte[] key;
                ExternalVaultHeader header;
                if (hasContent)
                {
                    try
                    {
                        header = await ReadHeaderAsync(path).ConfigureAwait(false);
                        var existingSalt = Convert.FromBase64String(header.Salt);
                        key = await Task.Run(() => DeriveKey(password, existingSalt, header.Iterations)).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is not InvalidOperationException)
                    {
                        throw new InvalidOperationException("Die Datei existiert bereits, ist aber keine gültige Sync-Datei.", ex);
                    }
                }
                else
                {
                    NewPasswordPolicy.Validate(password, nameof(password));
                    var salt = RandomNumberGenerator.GetBytes(SaltSize);
                    key = await Task.Run(() => DeriveKey(password, salt, Iterations)).ConfigureAwait(false);
                    header = new ExternalVaultHeader
                    {
                        Version = 1,
                        Salt = Convert.ToBase64String(salt),
                        Verifier = Convert.ToBase64String(CreateVerifier(key)),
                        Iterations = Iterations
                    };
                }

                try
                {
                    if (hasContent)
                    {
                        var expectedVerifier = Convert.FromBase64String(header.Verifier);
                        var actualVerifier = CreateVerifier(key);
                        if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
                            throw new InvalidOperationException("Das angegebene Passwort stimmt nicht mit der existierenden Sync-Datei überein.");
                        // The verifier alone does not prove that the encrypted content belongs to this key.
                        await ReadVaultFileAsync(path, key).ConfigureAwait(false);
                    }
                    else
                    {
                        await WriteVaultFileAsync(path, header, new ExternalVaultContent(), key).ConfigureAwait(false);
                    }

                    var encryptedKey = _appLockService.EncryptWithMasterKey(key);
                    await SecureStorage.Default.SetAsync(SyncKeyStorageKey, Convert.ToBase64String(encryptedKey)).ConfigureAwait(false);
                    Preferences.Set(SyncPathKey, path);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }
            }
            finally
            {
                _fileLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public Task ClearConfigurationAsync()
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            Preferences.Remove(SyncPathKey);
            Preferences.Remove(SyncAccessModeKey);
            SecureStorage.Default.Remove(SyncKeyStorageKey);
            return Task.CompletedTask;
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public Task<SyncAccessMode> GetAccessModeAsync()
    {
        var storedValue = Preferences.Get(SyncAccessModeKey, nameof(SyncAccessMode.ReadWrite));
        return Task.FromResult(Enum.TryParse(storedValue, out SyncAccessMode mode) ? mode : SyncAccessMode.ReadWrite);
    }

    public Task SetAccessModeAsync(SyncAccessMode mode)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            Preferences.Set(SyncAccessModeKey, mode.ToString());
            return Task.CompletedTask;
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<bool> ValidatePasswordAsync(string password)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            var path = Preferences.Get(SyncPathKey, string.Empty);
            if (string.IsNullOrEmpty(path)) return false;
            if (!await _syncFileService.ExistsAsync(path)) return false;

            try
            {
                var header = await ReadHeaderAsync(path);
                var salt = Convert.FromBase64String(header.Salt);
                var key = DeriveKey(password, salt, header.Iterations);
                try
                {
                    var expectedVerifier = Convert.FromBase64String(header.Verifier);
                    var actualVerifier = CreateVerifier(key);
                    if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier)) return false;
                    await ReadVaultFileAsync(path, key).ConfigureAwait(false);
                    return true;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }
            }
            catch
            {
                return false;
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public Task<bool> HasConfigurationAsync()
    {
        var path = Preferences.Get(SyncPathKey, string.Empty);
        return Task.FromResult(!string.IsNullOrWhiteSpace(path));
    }

    public async Task<bool> IsConfiguredAsync()
    {
        var path = Preferences.Get(SyncPathKey, string.Empty);
        if (string.IsNullOrWhiteSpace(path)) return false;

        try
        {
            return await _syncFileService.ExistsAsync(path).ConfigureAwait(false);
        }
        catch
        {
            // Automatic sync for the other vaults remains best effort when offline.
            return false;
        }
    }

    private async Task<KeyLease> GetKeyAsync()
    {
        if (!_appLockService.IsUnlocked) throw new InvalidOperationException("App locked.");

        var encryptedKeyStr = await SecureStorage.Default.GetAsync(SyncKeyStorageKey);
        if (string.IsNullOrEmpty(encryptedKeyStr)) throw new InvalidOperationException("Sync not configured.");

        var encryptedKey = Convert.FromBase64String(encryptedKeyStr);
        return new KeyLease(_appLockService.DecryptWithMasterKey(encryptedKey));
    }

    private sealed class KeyLease(byte[] key) : IDisposable
    {
        public byte[] Key { get; } = key;
        public void Dispose() => CryptographicOperations.ZeroMemory(Key);
    }

    private string GetPath()
    {
        var path = Preferences.Get(SyncPathKey, string.Empty);
        if (string.IsNullOrEmpty(path)) throw new InvalidOperationException("Sync path not configured.");
        return path;
    }

    public async Task SyncPasswordVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            // Use GetMergedPasswordVaultAsync which handles reading, merging, and WRITING back to the file.
            var result = await GetMergedPasswordVaultAsync(localEntries, cancellationToken);

            // Critical: Update the local list instance so the UI sees the changes!
            localEntries.Clear();
            foreach (var entry in result.MergedEntries)
            {
                localEntries.Add(entry);
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task SyncDataVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            var path = GetPath();
            using var keyLease = await GetKeyAsync();
            var key = keyLease.Key;

            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                var (header, content) = await ReadVaultFileAsync(path, key);

                var remoteEntries = content.DataVault.Select(d => d.ToModel()).ToList();
                var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);

                if (content.DataVault.Any(d => d.Id == Guid.Empty || d.ModifiedAt == default) ||
                    !PasswordEntrySetComparer.AreEquivalent(remoteEntries, result.MergedEntries))
                {
                    content.DataVault = result.MergedEntries
                        .Select(PasswordVaultEntryDto.FromModel)
                        .ToList();
                    content.LastModified = DateTimeOffset.UtcNow;
                    await WriteVaultFileAsync(path, header, content, key).ConfigureAwait(false);
                }

                localEntries.Clear();
                foreach(var e in result.MergedEntries) localEntries.Add(e);
            }
            finally
            {
                _fileLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task SyncAuthenticatorAsync(IList<TotpEntry> localEntries, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            var result = await GetMergedAuthenticatorAsync(localEntries, cancellationToken).ConfigureAwait(false);
            localEntries.Clear();
            foreach (var entry in result.MergedEntries) localEntries.Add(entry);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedPasswordVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
             var path = GetPath();
            using var keyLease = await GetKeyAsync();
            var key = keyLease.Key;

            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                var (header, content) = await ReadVaultFileAsync(path, key);

                var remoteEntries = content.PasswordVault.Select(d => d.ToModel()).ToList();
                var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);

                if (content.PasswordVault.Any(d => d.Id == Guid.Empty || d.ModifiedAt == default) ||
                    !PasswordEntrySetComparer.AreEquivalent(remoteEntries, result.MergedEntries))
                {
                    content.PasswordVault = result.MergedEntries
                        .Select(PasswordVaultEntryDto.FromModel)
                        .ToList();
                    content.LastModified = DateTimeOffset.UtcNow;
                    await WriteVaultFileAsync(path, header, content, key).ConfigureAwait(false);
                }

                return result;
            }
            finally
            {
                _fileLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedDataVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
             var path = GetPath();
            using var keyLease = await GetKeyAsync();
            var key = keyLease.Key;

            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                var (header, content) = await ReadVaultFileAsync(path, key);

                var remoteEntries = content.DataVault.Select(d => d.ToModel()).ToList();
                var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);

                if (content.DataVault.Any(d => d.Id == Guid.Empty || d.ModifiedAt == default) ||
                    !PasswordEntrySetComparer.AreEquivalent(remoteEntries, result.MergedEntries))
                {
                    content.DataVault = result.MergedEntries
                        .Select(PasswordVaultEntryDto.FromModel)
                        .ToList();
                    content.LastModified = DateTimeOffset.UtcNow;
                    await WriteVaultFileAsync(path, header, content, key).ConfigureAwait(false);
                }

                return result;
            }
            finally
            {
                _fileLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<Services.Vault.MergeResult<TotpEntry>> GetMergedAuthenticatorAsync(IList<TotpEntry> localEntries, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
             var path = GetPath();
            using var keyLease = await GetKeyAsync();
            var key = keyLease.Key;

            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                var (header, content) = await ReadVaultFileWithRetryAsync(path, key, cancellationToken).ConfigureAwait(false);

                var remoteEntries = content.Authenticator.Select(d => d.ToModel()).ToList();
                var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);

                if (!TotpEntrySetComparer.AreEquivalent(remoteEntries, result.MergedEntries))
                {
                    content.Authenticator = result.MergedEntries
                        .Select(TotpEntryDto.FromModel)
                        .ToList();
                    content.LastModified = DateTimeOffset.UtcNow;
                    await WriteVaultFileAsync(path, header, content, key).ConfigureAwait(false);
                }

                return result;
            }
            finally
            {
                _fileLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedPasswordVaultReadOnlyAsync(
        IList<PasswordVaultEntry> localEntries,
        CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            var path = GetPath();
            using var keyLease = await GetKeyAsync();
            var key = keyLease.Key;

            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                var (_, content) = await ReadVaultFileAsync(path, key);
                var remoteEntries = content.PasswordVault.Select(d => d.ToModel()).ToList();
                return _vaultMergeService.MergeEntries(localEntries, remoteEntries);
            }
            finally
            {
                _fileLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedDataVaultReadOnlyAsync(
        IList<PasswordVaultEntry> localEntries,
        CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            var path = GetPath();
            using var keyLease = await GetKeyAsync();
            var key = keyLease.Key;

            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                var (_, content) = await ReadVaultFileAsync(path, key);
                var remoteEntries = content.DataVault.Select(d => d.ToModel()).ToList();
                return _vaultMergeService.MergeEntries(localEntries, remoteEntries);
            }
            finally
            {
                _fileLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<Services.Vault.MergeResult<TotpEntry>> GetMergedAuthenticatorReadOnlyAsync(
        IList<TotpEntry> localEntries,
        CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            var path = GetPath();
            using var keyLease = await GetKeyAsync();
            var key = keyLease.Key;

            await _fileLock.WaitAsync(cancellationToken);
            try
            {
                var (_, content) = await ReadVaultFileWithRetryAsync(path, key, cancellationToken).ConfigureAwait(false);
                var remoteEntries = content.Authenticator.Select(d => d.ToModel()).ToList();
                return _vaultMergeService.MergeEntries(localEntries, remoteEntries);
            }
            finally
            {
                _fileLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    private const string MagicHeader = "PPP1"; // Password Phrase Producer v1

    private async Task<(ExternalVaultHeader Header, ExternalVaultContent Content)> ReadVaultFileWithRetryAsync(
        string path, byte[] key, CancellationToken cancellationToken)
    {
        // SAF cloud documents can briefly expose an incomplete revision. Reopen the entire
        // document on retry; every candidate must still pass the normal header and AEAD checks.
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await ReadVaultFileAsync(path, key).ConfigureAwait(false);
            }
            catch (Exception ex) when (attempt < 2 &&
                ex is IOException or InvalidDataException or JsonException or CryptographicException or FormatException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(attempt == 0 ? 250 : 600), cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    private async Task<(ExternalVaultHeader Header, ExternalVaultContent Content)> ReadVaultFileAsync(string path, byte[] key)
    {
        string json;
        using (var stream = await _syncFileService.OpenReadAsync(path))
        {
            json = await SyncFileReader.ReadJsonAsync(stream);
        }

        var file = JsonSerializer.Deserialize<ExternalVaultFile>(json, _jsonOptions);
        if (file == null) throw new InvalidDataException("Invalid sync file.");
        ValidateHeader(file.Header);

        if (string.IsNullOrEmpty(file.CipherText)) throw new InvalidDataException("Sync file has no content (CipherText empty).");

        var encryptedBytes = Convert.FromBase64String(file.CipherText);
        if (encryptedBytes.Length < 28) throw new InvalidDataException("Sync file content invalid (too short).");

        var plainBytes = DecryptWithKey(encryptedBytes, key);
        try
        {
            var content = JsonSerializer.Deserialize<ExternalVaultContent>(plainBytes, _jsonOptions)
                          ?? throw new InvalidDataException("Sync file content is invalid.");
            if (content.PasswordVault is null || content.DataVault is null || content.Authenticator is null)
                throw new InvalidDataException("Sync file content is incomplete.");
            return (file.Header, content);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }

    private async Task<ExternalVaultHeader> ReadHeaderAsync(string path)
    {
        string json;
        // Use Abstracted OpenRead
        using (var stream = await _syncFileService.OpenReadAsync(path))
        {
            json = await SyncFileReader.ReadJsonAsync(stream);
        }
        var file = JsonSerializer.Deserialize<ExternalVaultFile>(json, _jsonOptions);
        var header = file?.Header ?? throw new InvalidDataException("Invalid sync file format.");
        ValidateHeader(header);
        return header;
    }

    private static void ValidateHeader(ExternalVaultHeader header)
    {
        if (header.Version != 1 || header.Iterations is < 10_000 or > 1_000_000 ||
            !TryDecodeLength(header.Salt, SaltSize) || !TryDecodeLength(header.Verifier, 32))
            throw new InvalidDataException("Sync file header is invalid.");
    }

    private static bool TryDecodeLength(string? value, int length)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        try { return Convert.FromBase64String(value).Length == length; }
        catch (FormatException) { return false; }
    }

    private async Task WriteVaultFileAsync(string path, ExternalVaultHeader header, ExternalVaultContent content, byte[] key)
    {
        var plainBytes = JsonSerializer.SerializeToUtf8Bytes(content, _jsonOptions);
        byte[] encryptedBytes;
        try { encryptedBytes = EncryptWithKey(plainBytes, key); }
        finally { CryptographicOperations.ZeroMemory(plainBytes); }

        var file = new ExternalVaultFile
        {
            Header = header,
            CipherText = Convert.ToBase64String(encryptedBytes)
        };

        var json = JsonSerializer.Serialize(file, _jsonOptions);
        var jsonBytes = Encoding.UTF8.GetBytes(json);
        var length = jsonBytes.Length;
        if (length > SyncFileReader.MaxJsonBytes)
            throw new InvalidDataException("Sync file exceeds the supported size.");
        var lengthBytes = BitConverter.GetBytes(length);
        var magicBytes = Encoding.UTF8.GetBytes(MagicHeader);

        var fileBytes = new byte[magicBytes.Length + lengthBytes.Length + jsonBytes.Length];
        Buffer.BlockCopy(magicBytes, 0, fileBytes, 0, magicBytes.Length);
        Buffer.BlockCopy(lengthBytes, 0, fileBytes, magicBytes.Length, lengthBytes.Length);
        Buffer.BlockCopy(jsonBytes, 0, fileBytes, magicBytes.Length + lengthBytes.Length, jsonBytes.Length);
        await _syncFileService.WriteAllBytesAsync(path, fileBytes);
        // Any extra bytes after this (from failed truncation) will be ignored by the reader.
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(KeySize);
    }

    private static byte[] CreateVerifier(byte[] key)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(key);
    }

    private static byte[] EncryptWithKey(byte[] data, byte[] key)
    {
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

    private static byte[] DecryptWithKey(byte[] data, byte[] key)
    {
        if (data.Length < 28) throw new ArgumentException("Invalid encrypted data");

        var nonce = new byte[12];
        var tag = new byte[16];
        var cipherSize = data.Length - 12 - 16;
        var cipher = new byte[cipherSize];

        Buffer.BlockCopy(data, 0, nonce, 0, 12);
        Buffer.BlockCopy(data, 12 + cipherSize, tag, 0, 16);
        Buffer.BlockCopy(data, 12, cipher, 0, cipherSize);

        var plain = new byte[cipherSize];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, cipher, tag, plain);
            return plain;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plain);
            throw;
        }
    }
}
