using System.Collections.Generic;
using System.Globalization;
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
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Storage;

namespace Password_Phrase_Producer.Services.Vault;

public static class DataVaultMessages
{
    public const string EntriesChanged = nameof(EntriesChanged);
}

public class DataVaultService
{
    private const string VaultFileName = "data-vault.json.enc";
    private const string PasswordSaltStorageKey = "DataVaultMasterPasswordSalt";
    private const string PasswordVerifierStorageKey = "DataVaultMasterPasswordVerifier";
    private const string PasswordIterationsStorageKey = "DataVaultMasterPasswordIterations";
    private const string BiometricKeyStorageKey = "DataVaultBiometricKey_V2"; // New version for secure storage

    private const int KeySizeBytes = 32;
    private const int SaltSizeBytes = 16;
    private const int Pbkdf2Iterations = 200_000;
    private const int VaultFileFormatVersion = 1;

    private const string LastEntryCountStorageKey = "DataVaultLastEntryCount";

    private readonly SemaphoreSlim _syncLock = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private readonly IBiometricAuthenticationService _biometricService;
    private readonly ISecureFileService _secureFileService;
    private readonly VaultMergeService _vaultMergeService;
    private readonly Services.Synchronization.ISynchronizationService _syncService;
    private readonly string _vaultFilePath;
    private byte[]? _encryptionKey;

    public DataVaultService(
        IBiometricAuthenticationService biometricService, 
        ISecureFileService secureFileService, 
        VaultMergeService vaultMergeService,
        Services.Synchronization.ISynchronizationService syncService)
    {
        _biometricService = biometricService;
        _secureFileService = secureFileService;
        _vaultMergeService = vaultMergeService;
        _syncService = syncService;
        _vaultFilePath = Path.Combine(FileSystem.AppDataDirectory, VaultFileName);
    }

    public bool IsUnlocked => _encryptionKey is not null;

    public async Task<bool> HasMasterPasswordAsync(CancellationToken cancellationToken = default)
    {
        var metadata = await GetPasswordMetadataAsync(cancellationToken).ConfigureAwait(false);
        return !string.IsNullOrEmpty(metadata.Salt);
    }

    public async Task<bool> HasBiometricKeyAsync(CancellationToken cancellationToken = default)
    {
        var stored = await SecureStorage.Default.GetAsync(BiometricKeyStorageKey).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(stored))
        {
            return true;
        }

        return false;
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
        var key = DeriveKey(password, salt, Pbkdf2Iterations);
        var verifier = CreateVerifier(key);

        await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, Convert.ToBase64String(salt)).ConfigureAwait(false);
        await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, Convert.ToBase64String(verifier)).ConfigureAwait(false);
        await SetStoredPbkdf2IterationsAsync(Pbkdf2Iterations).ConfigureAwait(false);

        _encryptionKey = key;
        UpdateStoredEntryCount(0);

        if (enableBiometrics)
        {
             await SetBiometricUnlockAsync(true, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            SecureStorage.Default.Remove(BiometricKeyStorageKey);
        }
    }

    public async Task<bool> UnlockAsync(string password, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var metadata = await GetPasswordMetadataAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(metadata.Salt) || string.IsNullOrEmpty(metadata.Verifier))
        {
            return false;
        }

        var salt = Convert.FromBase64String(metadata.Salt);
        var iterations = metadata.Iterations;
        var key = DeriveKey(password, salt, iterations);
        var expectedVerifier = Convert.FromBase64String(metadata.Verifier);
        var actualVerifier = CreateVerifier(key);

        if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
        {
            Array.Clear(key);
            return false;
        }

        _encryptionKey = key;
        
        if (await _syncService.IsConfiguredAsync().ConfigureAwait(false))
        {
            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                await _syncService.SyncDataVaultAsync(entries, cancellationToken).ConfigureAwait(false);
                await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Sync fail ignored
            }
            finally
            {
                _syncLock.Release();
            }
            MessagingCenter.Send(this, DataVaultMessages.EntriesChanged);
        }

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
            var newKey = DeriveKey(newPassword, newSalt, Pbkdf2Iterations);
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
            await SetStoredPbkdf2IterationsAsync(Pbkdf2Iterations).ConfigureAwait(false);

            if (enableBiometrics)
            {
                await SetBiometricUnlockAsync(true, cancellationToken).ConfigureAwait(false);
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
        var metadata = await GetPasswordMetadataAsync(cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrEmpty(storedKeyBase64) || string.IsNullOrEmpty(metadata.Verifier))
        {

            return false;
        }

        try 
        {
            var encryptedKey = Convert.FromBase64String(storedKeyBase64);
            var key = await _biometricService.DecryptAsync(encryptedKey, cancellationToken).ConfigureAwait(false);

            var expectedVerifier = Convert.FromBase64String(metadata.Verifier);
            var actualVerifier = CreateVerifier(key);

            if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
            {
                SecureStorage.Default.Remove(BiometricKeyStorageKey);
                Array.Clear(key);
                return false;
            }

            _encryptionKey = key;
            
            if (await _syncService.IsConfiguredAsync().ConfigureAwait(false))
            {
                await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                    await _syncService.SyncDataVaultAsync(entries, cancellationToken).ConfigureAwait(false);
                    await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    // Sync fail ignored
                }
                finally
                {
                    _syncLock.Release();
                }
                MessagingCenter.Send(this, DataVaultMessages.EntriesChanged);
            }

            return true;
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (Exception)
        {
             return false;
        }
    }

    public async Task SetBiometricUnlockAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        if (!IsUnlocked)
        {
            throw new InvalidOperationException("Der Datentresor ist gesperrt.");
        }

        if (enabled)
        {
            try 
            {
                var encrypted = await _biometricService.EncryptAsync(_encryptionKey!, cancellationToken).ConfigureAwait(false);
                await SecureStorage.Default.SetAsync(BiometricKeyStorageKey, Convert.ToBase64String(encrypted)).ConfigureAwait(false);
            }
            catch (Exception)
            {
                 SecureStorage.Default.Remove(BiometricKeyStorageKey);
            }
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

            if (await _syncService.IsConfiguredAsync().ConfigureAwait(false))
            {
                try
                {
                    await _syncService.SyncDataVaultAsync(entries, cancellationToken).ConfigureAwait(false);
                    Preferences.Set("DataVaultLastSync", DateTime.Now);
                }
                catch
                {
                }
            }

            await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }

        MessagingCenter.Send(this, DataVaultMessages.EntriesChanged);
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
                if (await _syncService.IsConfiguredAsync().ConfigureAwait(false))
                {
                    try
                    {
                        await _syncService.SyncDataVaultAsync(entries, cancellationToken).ConfigureAwait(false);
                        Preferences.Set("DataVaultLastSync", DateTime.Now);
                    }
                    catch
                    {
                    }
                }
                await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _syncLock.Release();
        }

        MessagingCenter.Send(this, DataVaultMessages.EntriesChanged);
    }

    public async Task SyncNowAsync(CancellationToken cancellationToken = default)
    {
        if (!IsUnlocked) return;
        
        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            if (await _syncService.IsConfiguredAsync().ConfigureAwait(false))
            {
                await _syncService.SyncDataVaultAsync(entries, cancellationToken).ConfigureAwait(false);
                await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _syncLock.Release();
        }
    }

    public async Task<byte[]> ExportWithFilePasswordAsync(string filePassword, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePassword);
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
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
            var plainBytes = Encoding.UTF8.GetBytes(json);

            try
            {
                var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
                var key = DeriveKey(filePassword, salt, Pbkdf2Iterations);
                try
                {
                    var encrypted = EncryptWithKey(plainBytes, key);
                    var verifier = CreateVerifier(key);

                    var exportDto = new PortableBackupDto
                    {
                        Salt = Convert.ToBase64String(salt),
                        Verifier = Convert.ToBase64String(verifier),
                        Iterations = Pbkdf2Iterations,
                        CipherText = Convert.ToBase64String(encrypted),
                        CreatedAt = DateTimeOffset.UtcNow
                    };

                    return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(exportDto, _jsonOptions));
                }
                finally
                {
                    Array.Clear(key);
                }
            }
            finally
            {
                Array.Clear(plainBytes);
            }
        }
        finally
        {
            _syncLock.Release();
        }
    }

    public async Task ImportWithFilePasswordAsync(Stream stream, string filePassword, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentException.ThrowIfNullOrWhiteSpace(filePassword);
        EnsureUnlocked();

        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        var json = await reader.ReadToEndAsync().ConfigureAwait(false);
        var dto = JsonSerializer.Deserialize<PortableBackupDto>(json, _jsonOptions)
                  ?? throw new InvalidOperationException("Ungültiges Export-Format.");

        var salt = Convert.FromBase64String(dto.Salt);
        var key = DeriveKey(filePassword, salt, dto.Iterations);

        var expectedVerifier = Convert.FromBase64String(dto.Verifier);
        var actualVerifier = CreateVerifier(key);
        if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
        {
            Array.Clear(key);
            throw new InvalidOperationException("Falsches Datei-Passwort.");
        }

        var encrypted = Convert.FromBase64String(dto.CipherText);
        var plainBytes = DecryptWithKey(encrypted, key);
        Array.Clear(key);

        try
        {
            var snapshot = JsonSerializer.Deserialize<PasswordVaultSnapshotDto>(plainBytes, _jsonOptions)
                          ?? throw new InvalidOperationException("Ungültiges Snapshot-Format.");
            
            if (snapshot.Entries is null)
            {
                return;
            }

            var entries = snapshot.Entries.Select(e => e.ToModel()).ToList();

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var existingEntries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                var result = _vaultMergeService.MergeEntries(existingEntries, entries);
                await SaveEntriesInternalAsync(result.MergedEntries, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _syncLock.Release();
            }

            Lock();
            MessagingCenter.Send(this, DataVaultMessages.EntriesChanged);
        }
        finally
        {
            Array.Clear(plainBytes);
        }
    }

    private async Task<List<PasswordVaultEntry>> LoadEntriesInternalAsync(CancellationToken cancellationToken)
    {
        var vaultFile = await ReadVaultFileAsync(cancellationToken).ConfigureAwait(false);
        if (vaultFile.Cipher.Length == 0)
        {
            UpdateStoredEntryCount(0);
            return new List<PasswordVaultEntry>();
        }

        var decryptedBytes = await DecryptAsync(vaultFile.Cipher, cancellationToken).ConfigureAwait(false);
        try
        {
            if (decryptedBytes.Length == 0)
            {
                UpdateStoredEntryCount(0);
                return new List<PasswordVaultEntry>();
            }

            var json = Encoding.UTF8.GetString(decryptedBytes);
            var snapshot = JsonSerializer.Deserialize<PasswordVaultSnapshotDto>(json, _jsonOptions);

            if (snapshot?.Entries is null)
            {
                UpdateStoredEntryCount(0);
                return new List<PasswordVaultEntry>();
            }

            var entries = snapshot.Entries
                .Select(dto => dto.ToModel())
                .ToList();

            UpdateStoredEntryCount(entries.Count);
            return entries;
        }
        catch (Exception ex) when (ex is JsonException || ex is NotSupportedException)
        {
             throw new InvalidDataException("Die Datentresor-Datei ist beschädigt oder hat ein ungültiges Format.", ex);
        }
        finally
        {
            Array.Clear(decryptedBytes);
        }
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
        var plainBytes = Encoding.UTF8.GetBytes(json);
        try
        {
            var encrypted = await EncryptAsync(plainBytes, cancellationToken).ConfigureAwait(false);
            var vaultFile = await CreateVaultFileContentAsync(encrypted, cancellationToken).ConfigureAwait(false);

            await WriteVaultFileInternalAsync(vaultFile.RawContent, cancellationToken).ConfigureAwait(false);
            UpdateStoredEntryCount(ordered.Count);
        }
        finally
        {
            Array.Clear(plainBytes);
        }
    }

    private Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken)
    {
        var key = GetUnlockedKey();
        var result = EncryptWithKey(data, key);
        return Task.FromResult(result);
    }

    private Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken)
    {
        var key = GetUnlockedKey();
        var result = DecryptWithKey(data, key);
        return Task.FromResult(result);
    }

    private async Task<byte[]> ReadEncryptedFileAsync(CancellationToken cancellationToken)
    {
        var vaultFile = await ReadVaultFileAsync(cancellationToken).ConfigureAwait(false);
        if (vaultFile.RawContent.Length == 0)
        {
            return Array.Empty<byte>();
        }

        if (!string.IsNullOrWhiteSpace(vaultFile.PasswordSalt) && !string.IsNullOrWhiteSpace(vaultFile.PasswordVerifier))
        {
            return vaultFile.RawContent;
        }

        var salt = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey).ConfigureAwait(false);
        var verifier = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey).ConfigureAwait(false);

        if (string.IsNullOrEmpty(salt) || string.IsNullOrEmpty(verifier))
        {
            return vaultFile.RawContent;
        }

        var updatedContent = await CreateVaultFileContentAsync(vaultFile.Cipher, cancellationToken).ConfigureAwait(false);
        await WriteVaultFileInternalAsync(updatedContent.RawContent, cancellationToken).ConfigureAwait(false);
        return updatedContent.RawContent;
    }

    private async Task<VaultFileContent> ReadVaultFileAsync(CancellationToken cancellationToken)
    {
        if (!await _secureFileService.ExistsAsync(_vaultFilePath))
        {
            return VaultFileContent.Empty;
        }

        var rawContent = await _secureFileService.ReadAllBytesAsync(_vaultFilePath, cancellationToken).ConfigureAwait(false);
        return ParseVaultFile(rawContent);
    }

    private VaultFileContent ParseVaultFile(byte[] rawContent)
    {
        if (rawContent.Length == 0)
        {
            return VaultFileContent.Empty;
        }

        try
        {
            var json = Encoding.UTF8.GetString(rawContent);
            if (!string.IsNullOrWhiteSpace(json) && json.TrimStart().StartsWith("{", StringComparison.Ordinal))
            {
                var dto = JsonSerializer.Deserialize<EncryptedVaultFileDto>(json, _jsonOptions);
                if (dto is not null && !string.IsNullOrWhiteSpace(dto.CipherText))
                {
                    var cipher = Convert.FromBase64String(dto.CipherText);
                    return new VaultFileContent(cipher, dto.PasswordSalt, dto.PasswordVerifier, dto.Pbkdf2Iterations, rawContent);
                }

                return new VaultFileContent(Array.Empty<byte>(), dto?.PasswordSalt, dto?.PasswordVerifier, dto?.Pbkdf2Iterations, rawContent);
            }
        }
        catch (DecoderFallbackException)
        {
        }
        catch (JsonException)
        {
        }
        catch (FormatException)
        {
        }

        return new VaultFileContent(rawContent, null, null, null, rawContent);
    }

    private async Task<VaultFileContent> CreateVaultFileContentAsync(byte[] cipher, CancellationToken cancellationToken)
    {
        var salt = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey).ConfigureAwait(false)
                   ?? throw new InvalidOperationException("Kein Master-Passwort konfiguriert.");
        var verifier = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey).ConfigureAwait(false)
                      ?? throw new InvalidOperationException("Kein Master-Passwort konfiguriert.");
        var iterations = await GetStoredPbkdf2IterationsAsync().ConfigureAwait(false);

        var dto = new EncryptedVaultFileDto
        {
            Version = VaultFileFormatVersion,
            CipherText = Convert.ToBase64String(cipher),
            PasswordSalt = salt,
            PasswordVerifier = verifier,
            Pbkdf2Iterations = iterations
        };

        var rawContent = JsonSerializer.SerializeToUtf8Bytes(dto, _jsonOptions);
        return new VaultFileContent(cipher, salt, verifier, iterations, rawContent);
    }

    private async Task WriteVaultFileInternalAsync(byte[] rawContent, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_vaultFilePath)!);
        await _secureFileService.WriteAllBytesAsync(_vaultFilePath, rawContent, cancellationToken).ConfigureAwait(false);
    }

    private async Task<int?> TryGetEntryCountAsync(VaultFileContent content, CancellationToken cancellationToken)
    {
        if (content.Cipher.Length == 0)
        {
            UpdateStoredEntryCount(0);
            return 0;
        }

        byte[]? decrypted = null;
        try
        {
            decrypted = await DecryptAsync(content.Cipher, cancellationToken).ConfigureAwait(false);
            if (decrypted.Length == 0)
            {
                UpdateStoredEntryCount(0);
                return 0;
            }

            var snapshot = JsonSerializer.Deserialize<PasswordVaultSnapshotDto>(decrypted, _jsonOptions);
            var count = snapshot?.Entries?.Count ?? 0;
            UpdateStoredEntryCount(count);
            return count;
        }
        catch (InvalidOperationException)
        {
            return GetStoredEntryCount();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return GetStoredEntryCount();
        }
        finally
        {
            if (decrypted is not null)
            {
                Array.Clear(decrypted);
            }
        }
    }

    private void UpdateStoredEntryCount(int count)
    {
        Preferences.Default.Set(LastEntryCountStorageKey, Math.Max(0, count));
    }

    private int? GetStoredEntryCount()
    {
        var stored = Preferences.Default.Get(LastEntryCountStorageKey, -1);
        return stored >= 0 ? stored : null;
    }

    private void ClearStoredEntryCount()
    {
        Preferences.Default.Remove(LastEntryCountStorageKey);
    }

    private async Task<PasswordMetadata> GetPasswordMetadataAsync(CancellationToken cancellationToken)
    {
        var salt = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey).ConfigureAwait(false);
        var verifier = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey).ConfigureAwait(false);
        var iterations = await GetStoredPbkdf2IterationsAsync().ConfigureAwait(false);

        if (!string.IsNullOrEmpty(salt) && !string.IsNullOrEmpty(verifier))
        {
            return new PasswordMetadata(salt, verifier, iterations);
        }

        var vaultFile = await ReadVaultFileAsync(cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(vaultFile.PasswordSalt) && !string.IsNullOrWhiteSpace(vaultFile.PasswordVerifier))
        {
            var vaultIterations = vaultFile.Pbkdf2Iterations.HasValue && vaultFile.Pbkdf2Iterations.Value > 0
                ? vaultFile.Pbkdf2Iterations.Value
                : Pbkdf2Iterations;
            return new PasswordMetadata(vaultFile.PasswordSalt, vaultFile.PasswordVerifier, vaultIterations);
        }

        return new PasswordMetadata(null, null, iterations);
    }

    private sealed record PasswordMetadata(string? Salt, string? Verifier, int Iterations);

    private async Task UpdatePasswordMetadataAsync(VaultFileContent content)
    {
        if (string.IsNullOrWhiteSpace(content.PasswordSalt) || string.IsNullOrWhiteSpace(content.PasswordVerifier))
        {
            return;
        }

        await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, content.PasswordSalt).ConfigureAwait(false);
        await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, content.PasswordVerifier).ConfigureAwait(false);
        var iterations = content.Pbkdf2Iterations.HasValue && content.Pbkdf2Iterations.Value > 0
            ? content.Pbkdf2Iterations.Value
            : Pbkdf2Iterations;
        await SetStoredPbkdf2IterationsAsync(iterations).ConfigureAwait(false);
        SecureStorage.Default.Remove(BiometricKeyStorageKey);
    }

    private sealed record VaultFileContent(byte[] Cipher, string? PasswordSalt, string? PasswordVerifier, int? Pbkdf2Iterations, byte[] RawContent)
    {
        public static VaultFileContent Empty { get; } = new(Array.Empty<byte>(), null, null, null, Array.Empty<byte>());
    }

    internal byte[] GetUnlockedKey()
    {
        if (_encryptionKey is null)
        {
            throw new InvalidOperationException("Der Datentresor ist gesperrt.");
        }

        return _encryptionKey.ToArray();
    }

    private void EnsureUnlocked()
    {
        if (!IsUnlocked)
        {
            throw new InvalidOperationException("Der Datentresor ist gesperrt.");
        }
    }

    private async Task<int> GetStoredPbkdf2IterationsAsync()
    {
        var storedValue = await SecureStorage.Default.GetAsync(PasswordIterationsStorageKey).ConfigureAwait(false);
        if (int.TryParse(storedValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var iterations) && iterations > 0)
        {
            return iterations;
        }

        return Pbkdf2Iterations;
    }

    private static Task SetStoredPbkdf2IterationsAsync(int iterations)
    {
        var effective = iterations > 0 ? iterations : Pbkdf2Iterations;
        return SecureStorage.Default.SetAsync(PasswordIterationsStorageKey, effective.ToString(CultureInfo.InvariantCulture));
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(KeySizeBytes);
    }

    private static byte[] CreateVerifier(byte[] key)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(key);
    }

    internal static byte[] EncryptWithKey(byte[] data, byte[] key)
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

    internal static byte[] DecryptWithKey(byte[] data, byte[] key)
    {
        const int nonceLength = 12;
        const int tagLength = 16;

        if (data.Length < nonceLength + tagLength)
        {
            return Array.Empty<byte>();
        }

        var cipherLength = data.Length - nonceLength - tagLength;
        if (cipherLength < 0)
        {
            throw new InvalidOperationException("Ungültiges verschlüsseltes Format.");
        }

        var nonce = new byte[nonceLength];
        var cipher = new byte[cipherLength];
        var tag = new byte[tagLength];

        Buffer.BlockCopy(data, 0, nonce, 0, nonceLength);
        Buffer.BlockCopy(data, nonceLength, cipher, 0, cipherLength);
        Buffer.BlockCopy(data, nonceLength + cipherLength, tag, 0, tagLength);

        var plain = new byte[cipherLength];
        using var aes = new AesGcm(key, tagLength);
        aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    public async Task<MergeResult<PasswordVaultEntry>> MergeEntriesAsync(
        IList<PasswordVaultEntry> incomingEntries,
        CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var existingEntries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            var mergeService = new VaultMergeService();
            var result = mergeService.MergeEntries(existingEntries, incomingEntries);

            await SaveEntriesInternalAsync(result.MergedEntries, cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally
        {
            _syncLock.Release();
        }
    }

    public async Task RestoreBackupWithMergeAsync(Stream backupStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(backupStream);
        EnsureUnlocked();

        using var reader = new StreamReader(backupStream, Encoding.UTF8, leaveOpen: true);
        var json = await reader.ReadToEndAsync().ConfigureAwait(false);
        var dto = JsonSerializer.Deserialize<PasswordVaultBackupDto>(json, _jsonOptions)
                  ?? throw new InvalidOperationException("Ungültiges Backup-Format.");

        var cipher = Convert.FromBase64String(dto.CipherText);

        try
        {
            var decryptedBytes = await DecryptAsync(cipher, cancellationToken).ConfigureAwait(false);
            if (decryptedBytes.Length == 0)
            {
                throw new InvalidOperationException("Entschlüsselung fehlgeschlagen. Möglicherweise unterschiedliche Passwörter.");
            }

            var snapshot = JsonSerializer.Deserialize<PasswordVaultSnapshotDto>(decryptedBytes, _jsonOptions);
            if (snapshot?.Entries is null)
            {
                return;
            }

            var incomingEntries = snapshot.Entries.Select(e => e.ToModel()).ToList();
            await MergeEntriesAsync(incomingEntries, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            throw new InvalidOperationException("Merge fehlgeschlagen. Die Passwörter der Backups müssen übereinstimmen.");
        }

        MessagingCenter.Send(this, DataVaultMessages.EntriesChanged);
    }

    public async Task ResetVaultAsync(CancellationToken cancellationToken = default)
    {
        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Lock the vault
            Lock();

            // Delete vault file
            if (await _secureFileService.ExistsAsync(_vaultFilePath))
            {
                _secureFileService.Delete(_vaultFilePath);
            }

            // Clear SecureStorage entries
            SecureStorage.Default.Remove(PasswordSaltStorageKey);
            SecureStorage.Default.Remove(PasswordVerifierStorageKey);
            SecureStorage.Default.Remove(PasswordIterationsStorageKey);
            SecureStorage.Default.Remove(BiometricKeyStorageKey);

            // Clear entry count
            ClearStoredEntryCount();
        }
        finally
        {
            _syncLock.Release();
        }

        MessagingCenter.Send(this, DataVaultMessages.EntriesChanged);
    }
}
