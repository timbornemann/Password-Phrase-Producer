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
using Password_Phrase_Producer.Services.Vault.Sync;

namespace Password_Phrase_Producer.Services.Vault;

public static class VaultMessages
{
    public const string EntriesChanged = nameof(EntriesChanged);
    public const string SyncStatusChanged = nameof(SyncStatusChanged);
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

    private const string SyncConfigurationStorageKey = "PasswordVaultSyncConfiguration";
    private const string SyncStatusStorageKey = "PasswordVaultSyncStatus";
    private static readonly TimeSpan DefaultAutoSyncInterval = TimeSpan.FromMinutes(15);

    private readonly SemaphoreSlim _syncLock = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private readonly string _vaultFilePath;
    private readonly Dictionary<string, IVaultSyncProvider> _syncProviders;
    private readonly IVaultSyncScheduler _syncScheduler;
    private byte[]? _encryptionKey;

    public PasswordVaultService(IEnumerable<IVaultSyncProvider>? syncProviders = null, IVaultSyncScheduler? syncScheduler = null)
    {
        _vaultFilePath = Path.Combine(FileSystem.AppDataDirectory, VaultFileName);
        _syncProviders = (syncProviders ?? Array.Empty<IVaultSyncProvider>())
            .GroupBy(provider => provider.Key, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToDictionary(provider => provider.Key, provider => provider, StringComparer.OrdinalIgnoreCase);
        _syncScheduler = syncScheduler ?? new NoOpVaultSyncScheduler();

        _ = InitializeAutoSyncAsync();
    }

    public bool IsUnlocked => _encryptionKey is not null;

    public IEnumerable<VaultSyncProviderDescriptor> GetAvailableSyncProviders()
        => _syncProviders.Values
            .Select(provider => new VaultSyncProviderDescriptor(provider.Key, provider.DisplayName, provider.SupportsAutomaticSync))
            .OrderBy(descriptor => descriptor.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

    public async Task<VaultSyncConfiguration> GetSyncConfigurationAsync(CancellationToken cancellationToken = default)
    {
        await Task.Yield();
        var json = Preferences.Default.Get(SyncConfigurationStorageKey, string.Empty);
        if (string.IsNullOrWhiteSpace(json))
        {
            return new VaultSyncConfiguration();
        }

        var configuration = JsonSerializer.Deserialize<VaultSyncConfiguration>(json, _jsonOptions) ?? new VaultSyncConfiguration();
        configuration.Parameters = configuration.Parameters is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(configuration.Parameters, StringComparer.OrdinalIgnoreCase);
        return configuration;
    }

    public async Task<VaultSyncStatus> GetSyncStatusAsync(CancellationToken cancellationToken = default)
    {
        await Task.Yield();
        var json = Preferences.Default.Get(SyncStatusStorageKey, string.Empty);
        if (string.IsNullOrWhiteSpace(json))
        {
            return new VaultSyncStatus();
        }

        var status = JsonSerializer.Deserialize<VaultSyncStatus>(json, _jsonOptions) ?? new VaultSyncStatus();
        return status;
    }

    public async Task UpdateSyncConfigurationAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var clone = configuration.Clone();
        var json = JsonSerializer.Serialize(clone, _jsonOptions);
        Preferences.Default.Set(SyncConfigurationStorageKey, json);

        var status = await GetSyncStatusAsync(cancellationToken).ConfigureAwait(false);
        status.IsEnabled = clone.IsEnabled;
        status.AutoSyncEnabled = clone.AutoSyncEnabled;
        status.ProviderKey = clone.ProviderKey;
        await SaveSyncStatusAsync(status).ConfigureAwait(false);

        await ConfigureSchedulerAsync(clone, cancellationToken).ConfigureAwait(false);
        NotifySyncStatusChanged();
    }

    public async Task<VaultSyncResult> SynchronizeAsync(bool preferDownload = false, CancellationToken cancellationToken = default)
    {
        var configuration = await GetSyncConfigurationAsync(cancellationToken).ConfigureAwait(false);

        if (!configuration.IsEnabled)
        {
            var disabledResult = new VaultSyncResult { Operation = VaultSyncOperation.Disabled };
            await UpdateSyncStatusAsync(configuration, disabledResult, cancellationToken).ConfigureAwait(false);
            return disabledResult;
        }

        if (string.IsNullOrWhiteSpace(configuration.ProviderKey) || !_syncProviders.TryGetValue(configuration.ProviderKey, out var provider))
        {
            var result = new VaultSyncResult
            {
                Operation = VaultSyncOperation.NoProvider,
                ErrorMessage = "Es wurde kein gültiger Synchronisationsanbieter ausgewählt."
            };
            await UpdateSyncStatusAsync(configuration, result, cancellationToken).ConfigureAwait(false);
            return result;
        }

        if (!await provider.IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            var result = new VaultSyncResult
            {
                Operation = VaultSyncOperation.NoProvider,
                ErrorMessage = "Der ausgewählte Synchronisationsanbieter ist nicht vollständig konfiguriert."
            };
            await UpdateSyncStatusAsync(configuration, result, cancellationToken).ConfigureAwait(false);
            return result;
        }

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var localPayload = await ReadEncryptedFileAsync(cancellationToken).ConfigureAwait(false);
            var localState = CreateLocalRemoteState(localPayload);
            var remoteState = await provider.GetRemoteStateAsync(configuration, cancellationToken).ConfigureAwait(false);

            if (remoteState is null && localPayload.Length == 0)
            {
                var emptyResult = new VaultSyncResult
                {
                    Operation = VaultSyncOperation.UpToDate,
                    LocalState = localState
                };
                await UpdateSyncStatusAsync(configuration, emptyResult, cancellationToken).ConfigureAwait(false);
                return emptyResult;
            }

            if (remoteState is null)
            {
                await provider.UploadAsync(new VaultSyncUploadRequest
                {
                    Payload = localPayload,
                    LocalState = localState
                }, configuration, cancellationToken).ConfigureAwait(false);

                var uploadResult = new VaultSyncResult
                {
                    Operation = VaultSyncOperation.Uploaded,
                    LocalState = localState,
                    RemoteState = localState
                };
                await UpdateSyncStatusAsync(configuration, uploadResult, cancellationToken).ConfigureAwait(false);
                return uploadResult;
            }

            if (string.Equals(remoteState.MerkleHash, localState.MerkleHash, StringComparison.Ordinal))
            {
                var upToDate = new VaultSyncResult
                {
                    Operation = VaultSyncOperation.UpToDate,
                    LocalState = localState,
                    RemoteState = remoteState
                };
                await UpdateSyncStatusAsync(configuration, upToDate, cancellationToken).ConfigureAwait(false);
                return upToDate;
            }

            var shouldDownload = preferDownload;
            if (!shouldDownload)
            {
                shouldDownload = remoteState.LastModifiedUtc > localState.LastModifiedUtc;
            }

            if (!shouldDownload && localPayload.Length == 0)
            {
                shouldDownload = true;
            }

            if (shouldDownload)
            {
                var download = await provider.DownloadAsync(configuration, cancellationToken).ConfigureAwait(false);
                if (download is null)
                {
                    var error = new VaultSyncResult
                    {
                        Operation = VaultSyncOperation.Error,
                        ErrorMessage = "Die entfernten Tresordaten konnten nicht geladen werden."
                    };
                    await UpdateSyncStatusAsync(configuration, error, cancellationToken).ConfigureAwait(false);
                    return error;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(_vaultFilePath)!);
                await File.WriteAllBytesAsync(_vaultFilePath, download.Payload, cancellationToken).ConfigureAwait(false);
                File.SetLastWriteTimeUtc(_vaultFilePath, download.RemoteState.LastModifiedUtc.UtcDateTime);

                MessagingCenter.Send(this, VaultMessages.EntriesChanged);

                var refreshedState = CreateLocalRemoteState(download.Payload);
                var downloadResult = new VaultSyncResult
                {
                    Operation = VaultSyncOperation.Downloaded,
                    LocalState = refreshedState,
                    RemoteState = download.RemoteState
                };
                await UpdateSyncStatusAsync(configuration, downloadResult, cancellationToken).ConfigureAwait(false);
                return downloadResult;
            }

            await provider.UploadAsync(new VaultSyncUploadRequest
            {
                Payload = localPayload,
                LocalState = localState,
                RemoteStateBeforeUpload = remoteState
            }, configuration, cancellationToken).ConfigureAwait(false);

            var uploadConflictResult = new VaultSyncResult
            {
                Operation = VaultSyncOperation.Uploaded,
                LocalState = localState,
                RemoteState = localState
            };
            await UpdateSyncStatusAsync(configuration, uploadConflictResult, cancellationToken).ConfigureAwait(false);
            return uploadConflictResult;
        }
        catch (Exception ex)
        {
            var errorResult = new VaultSyncResult
            {
                Operation = VaultSyncOperation.Error,
                ErrorMessage = ex.Message
            };
            await UpdateSyncStatusAsync(configuration, errorResult, cancellationToken).ConfigureAwait(false);
            return errorResult;
        }
        finally
        {
            _syncLock.Release();
        }
    }

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

    private async Task InitializeAutoSyncAsync()
    {
        try
        {
            var configuration = await GetSyncConfigurationAsync().ConfigureAwait(false);
            await ConfigureSchedulerAsync(configuration).ConfigureAwait(false);
        }
        catch
        {
            // Hintergrund-Scheduling darf die App-Initialisierung nicht verhindern.
        }
    }

    private async Task ConfigureSchedulerAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        _syncScheduler.Cancel();

        if (!configuration.IsEnabled || !configuration.AutoSyncEnabled)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(configuration.ProviderKey) || !_syncProviders.TryGetValue(configuration.ProviderKey, out var provider))
        {
            return;
        }

        if (!provider.SupportsAutomaticSync)
        {
            return;
        }

        if (!await provider.IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        _syncScheduler.Schedule(DefaultAutoSyncInterval, RunScheduledSyncAsync);
    }

    private Task RunScheduledSyncAsync(CancellationToken cancellationToken)
        => SynchronizeAsync(false, cancellationToken);

    private async Task UpdateSyncStatusAsync(VaultSyncConfiguration configuration, VaultSyncResult result, CancellationToken cancellationToken)
    {
        var status = await GetSyncStatusAsync(cancellationToken).ConfigureAwait(false);
        status.IsEnabled = configuration.IsEnabled;
        status.AutoSyncEnabled = configuration.AutoSyncEnabled;
        status.ProviderKey = configuration.ProviderKey;
        status.LastOperation = result.Operation;

        if (result.Operation is VaultSyncOperation.Uploaded or VaultSyncOperation.Downloaded or VaultSyncOperation.UpToDate)
        {
            status.LastSyncUtc = DateTimeOffset.UtcNow;
            status.LastError = null;
            status.RemoteState = result.RemoteState ?? result.LocalState ?? status.RemoteState;
        }
        else if (result.Operation == VaultSyncOperation.Error)
        {
            status.LastError = result.ErrorMessage;
        }
        else
        {
            status.LastError = result.ErrorMessage;
        }

        await SaveSyncStatusAsync(status).ConfigureAwait(false);
        NotifySyncStatusChanged(result);
    }

    private Task SaveSyncStatusAsync(VaultSyncStatus status)
    {
        var json = JsonSerializer.Serialize(status, _jsonOptions);
        Preferences.Default.Set(SyncStatusStorageKey, json);
        return Task.CompletedTask;
    }

    private void NotifySyncStatusChanged(VaultSyncResult? result = null)
    {
        var payload = result ?? new VaultSyncResult { Operation = VaultSyncOperation.None };
        MessagingCenter.Send(this, VaultMessages.SyncStatusChanged, payload);
    }

    private VaultSyncRemoteState CreateLocalRemoteState(byte[] payload)
        => new()
        {
            LastModifiedUtc = GetLocalFileLastModifiedUtc(),
            ContentLength = payload.LongLength,
            MerkleHash = ComputeMerkleRoot(payload)
        };

    private DateTimeOffset GetLocalFileLastModifiedUtc()
    {
        if (!File.Exists(_vaultFilePath))
        {
            return DateTimeOffset.UtcNow;
        }

        var lastWrite = File.GetLastWriteTimeUtc(_vaultFilePath);
        if (lastWrite.Kind != DateTimeKind.Utc)
        {
            lastWrite = DateTime.SpecifyKind(lastWrite, DateTimeKind.Utc);
        }

        return new DateTimeOffset(lastWrite);
    }

    internal static string ComputeMerkleRoot(byte[] payload)
    {
        using var sha = SHA256.Create();
        if (payload.Length == 0)
        {
            var emptyHash = sha.ComputeHash(Array.Empty<byte>());
            return Convert.ToHexString(emptyHash);
        }

        const int chunkSize = 4 * 1024;
        var hashes = new List<byte[]>();
        for (var offset = 0; offset < payload.Length; offset += chunkSize)
        {
            var length = Math.Min(chunkSize, payload.Length - offset);
            hashes.Add(sha.ComputeHash(payload, offset, length));
        }

        while (hashes.Count > 1)
        {
            var nextLevel = new List<byte[]>((hashes.Count + 1) / 2);
            for (var i = 0; i < hashes.Count; i += 2)
            {
                var left = hashes[i];
                var right = i + 1 < hashes.Count ? hashes[i + 1] : left;
                var combined = new byte[left.Length + right.Length];
                Buffer.BlockCopy(left, 0, combined, 0, left.Length);
                Buffer.BlockCopy(right, 0, combined, left.Length, right.Length);
                nextLevel.Add(sha.ComputeHash(combined));
            }

            hashes = nextLevel;
        }

        return Convert.ToHexString(hashes[0]);
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
