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
    private const string PasswordIterationsStorageKey = "PasswordVaultMasterPasswordIterations";
    private const string BiometricKeyStorageKey = "PasswordVaultBiometricKey";
    private const int KeySizeBytes = 32;
    private const int SaltSizeBytes = 16;
    private const int Pbkdf2Iterations = 200_000;
    private const int VaultFileFormatVersion = 1;

    private const string SyncConfigurationStorageKey = "PasswordVaultSyncConfiguration";
    private const string SyncStatusStorageKey = "PasswordVaultSyncStatus";
    private const string RemotePasswordStoragePrefix = "PasswordVaultRemotePassword_";
    private const string LastEntryCountStorageKey = "PasswordVaultLastEntryCount";
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

    public async Task SetRemotePasswordAsync(string providerKey, string password, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var key = NormalizeRemoteProviderKey(providerKey);
        await SecureStorage.Default.SetAsync(GetRemotePasswordStorageKey(key), password.Trim()).ConfigureAwait(false);
    }

    public Task ClearRemotePasswordAsync(string providerKey, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);

        var key = NormalizeRemoteProviderKey(providerKey);
        SecureStorage.Default.Remove(GetRemotePasswordStorageKey(key));
        return Task.CompletedTask;
    }

    public async Task<bool> HasRemotePasswordAsync(string providerKey, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerKey);

        var key = NormalizeRemoteProviderKey(providerKey);
        var stored = await SecureStorage.Default.GetAsync(GetRemotePasswordStorageKey(key)).ConfigureAwait(false);
        return !string.IsNullOrEmpty(stored);
    }

    public async Task<VaultSyncRemoteState?> TryGetRemoteStateAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (string.IsNullOrWhiteSpace(configuration.ProviderKey)
            || !_syncProviders.TryGetValue(configuration.ProviderKey, out var provider))
        {
            return null;
        }

        if (!await provider.IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        try
        {
            return await provider.GetRemoteStateAsync(configuration, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    public async Task<RemoteVaultValidationResult> ValidateRemotePasswordAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (string.IsNullOrWhiteSpace(configuration.ProviderKey)
            || !_syncProviders.TryGetValue(configuration.ProviderKey, out var provider))
        {
            throw new InvalidOperationException("Es wurde kein gültiger Synchronisationsanbieter ausgewählt.");
        }

        if (!await provider.IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("Der ausgewählte Synchronisationsanbieter ist nicht vollständig konfiguriert.");
        }

        var remoteState = await provider.GetRemoteStateAsync(configuration, cancellationToken).ConfigureAwait(false);
        if (remoteState is null)
        {
            return new RemoteVaultValidationResult
            {
                RemoteExists = false,
                Success = true
            };
        }

        var download = await provider.DownloadAsync(configuration, cancellationToken).ConfigureAwait(false);
        if (download is null)
        {
            return new RemoteVaultValidationResult
            {
                RemoteExists = true,
                Success = false,
                ErrorMessage = "Die entfernten Tresordaten konnten nicht geladen werden."
            };
        }

        try
        {
            int? entryCount;
            if (RequiresRemotePassword(configuration.ProviderKey))
            {
                var snapshot = await ConvertRemotePayloadToLocalAsync(configuration.ProviderKey, download.Payload, cancellationToken).ConfigureAwait(false);
                entryCount = snapshot.Entries?.Count ?? 0;
            }
            else
            {
                var content = ParseVaultFile(download.Payload);
                entryCount = await TryGetEntryCountAsync(content, cancellationToken).ConfigureAwait(false);
            }

            return new RemoteVaultValidationResult
            {
                RemoteExists = true,
                Success = true,
                EntryCount = entryCount,
                RemoteState = download.RemoteState
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (LegacyRemoteVaultFormatException legacyEx)
        {
            return new RemoteVaultValidationResult
            {
                RemoteExists = true,
                Success = false,
                ErrorMessage = legacyEx.Message
            };
        }
        catch (Exception)
        {
            return new RemoteVaultValidationResult
            {
                RemoteExists = true,
                Success = false,
                ErrorMessage = "Remote-Passwort falsch oder Datei beschädigt."
            };
        }
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
        if (clone.IsEnabled)
        {
            TriggerImmediateSyncIfEnabled(preferDownload: true);
        }
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
            var requiresRemotePassword = RequiresRemotePassword(configuration.ProviderKey);
            if (requiresRemotePassword && !IsUnlocked)
            {
                var lockedResult = new VaultSyncResult
                {
                    Operation = VaultSyncOperation.Error,
                    ErrorMessage = "Bitte entsperre den Tresor, bevor du die Synchronisation ausführst."
                };
                await UpdateSyncStatusAsync(configuration, lockedResult, cancellationToken).ConfigureAwait(false);
                return lockedResult;
            }

            var (localPayload, localState) = await PrepareSyncPayloadAsync(configuration, cancellationToken).ConfigureAwait(false);
            var remoteState = await provider.GetRemoteStateAsync(configuration, cancellationToken).ConfigureAwait(false);
            int? initialEntryCount = null;

            if (remoteState is null && localPayload.Length == 0)
            {
                var emptyResult = new VaultSyncResult
                {
                    Operation = VaultSyncOperation.UpToDate,
                    LocalState = localState,
                    DownloadedEntries = 0,
                    UploadedEntries = 0
                };
                await UpdateSyncStatusAsync(configuration, emptyResult, cancellationToken).ConfigureAwait(false);
                return emptyResult;
            }

            if (remoteState is null)
            {
                initialEntryCount ??= await TryGetLocalEntryCountAsync(cancellationToken).ConfigureAwait(false);
                await provider.UploadAsync(new VaultSyncUploadRequest
                {
                    Payload = localPayload,
                    LocalState = localState
                }, configuration, cancellationToken).ConfigureAwait(false);

                var uploadResult = new VaultSyncResult
                {
                    Operation = VaultSyncOperation.Uploaded,
                    LocalState = localState,
                    RemoteState = localState,
                    UploadedEntries = initialEntryCount
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
                    RemoteState = remoteState,
                    DownloadedEntries = 0,
                    UploadedEntries = 0
                };
                await UpdateSyncStatusAsync(configuration, upToDate, cancellationToken).ConfigureAwait(false);
                return upToDate;
            }

            var shouldDownload = preferDownload;
            if (!shouldDownload && !requiresRemotePassword && !IsUnlocked && remoteState is not null)
            {
                shouldDownload = true;
            }

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

                if (requiresRemotePassword)
                {
                    var snapshot = await ConvertRemotePayloadToLocalAsync(configuration.ProviderKey, download.Payload, cancellationToken).ConfigureAwait(false);
                    var mergedEntries = await MergeRemoteEntriesAsync(snapshot, cancellationToken).ConfigureAwait(false);

                    if (mergedEntries > 0)
                    {
                        MessagingCenter.Send(this, VaultMessages.EntriesChanged);
                    }

                    var (refreshedPayload, refreshedState) = await PrepareSyncPayloadAsync(configuration, cancellationToken).ConfigureAwait(false);

                    await provider.UploadAsync(new VaultSyncUploadRequest
                    {
                        Payload = refreshedPayload,
                        LocalState = refreshedState,
                        RemoteStateBeforeUpload = download.RemoteState
                    }, configuration, cancellationToken).ConfigureAwait(false);

                    var totalEntries = await TryGetLocalEntryCountAsync(cancellationToken).ConfigureAwait(false);
                    var mergedResult = new VaultSyncResult
                    {
                        Operation = VaultSyncOperation.Downloaded,
                        LocalState = refreshedState,
                        RemoteState = refreshedState,
                        DownloadedEntries = mergedEntries,
                        UploadedEntries = totalEntries
                    };
                    await UpdateSyncStatusAsync(configuration, mergedResult, cancellationToken).ConfigureAwait(false);
                    return mergedResult;
                }

                var localFileContent = ParseVaultFile(download.Payload);
                await WriteVaultFileInternalAsync(localFileContent.RawContent, cancellationToken).ConfigureAwait(false);
                File.SetLastWriteTimeUtc(_vaultFilePath, download.RemoteState.LastModifiedUtc.UtcDateTime);
                await UpdatePasswordMetadataAsync(localFileContent).ConfigureAwait(false);

                MessagingCenter.Send(this, VaultMessages.EntriesChanged);

                var (_, downloadedState) = await PrepareSyncPayloadAsync(configuration, cancellationToken).ConfigureAwait(false);
                var downloadedCount = await TryGetLocalEntryCountAsync(cancellationToken).ConfigureAwait(false);
                var downloadResult = new VaultSyncResult
                {
                    Operation = VaultSyncOperation.Downloaded,
                    LocalState = downloadedState,
                    RemoteState = download.RemoteState,
                    DownloadedEntries = downloadedCount
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

            initialEntryCount ??= await TryGetLocalEntryCountAsync(cancellationToken).ConfigureAwait(false);
            var uploadConflictResult = new VaultSyncResult
            {
                Operation = VaultSyncOperation.Uploaded,
                LocalState = localState,
                RemoteState = localState,
                UploadedEntries = initialEntryCount
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
        await EnsurePasswordMetadataAsync(cancellationToken).ConfigureAwait(false);
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
        var key = DeriveKey(password, salt, Pbkdf2Iterations);
        var verifier = CreateVerifier(key);

        await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, Convert.ToBase64String(salt)).ConfigureAwait(false);
        await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, Convert.ToBase64String(verifier)).ConfigureAwait(false);
        await SetStoredPbkdf2IterationsAsync(Pbkdf2Iterations).ConfigureAwait(false);

        _encryptionKey = key;
        UpdateStoredEntryCount(0);

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

        await EnsurePasswordMetadataAsync(cancellationToken).ConfigureAwait(false);

        var saltBase64 = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey).ConfigureAwait(false);
        var verifierBase64 = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey).ConfigureAwait(false);

        if (string.IsNullOrEmpty(saltBase64) || string.IsNullOrEmpty(verifierBase64))
        {
            return false;
        }

        var salt = Convert.FromBase64String(saltBase64);
        var iterations = await GetStoredPbkdf2IterationsAsync().ConfigureAwait(false);
        var key = DeriveKey(password, salt, iterations);
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
        await EnsurePasswordMetadataAsync(cancellationToken).ConfigureAwait(false);

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
        TriggerImmediateSyncIfEnabled();
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
        TriggerImmediateSyncIfEnabled();
    }

    public async Task<byte[]> CreateBackupAsync(CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var vaultFile = await ReadVaultFileAsync(cancellationToken).ConfigureAwait(false);
            var encryptedPayload = vaultFile.Cipher;
            var iterations = await GetStoredPbkdf2IterationsAsync().ConfigureAwait(false);
            var salt = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey).ConfigureAwait(false)
                       ?? throw new InvalidOperationException("Kein Master-Passwort konfiguriert.");
            var verifier = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey).ConfigureAwait(false)
                          ?? throw new InvalidOperationException("Kein Master-Passwort konfiguriert.");

            var backup = new PasswordVaultBackupDto
            {
                CipherText = Convert.ToBase64String(encryptedPayload),
                PasswordSalt = salt,
                PasswordVerifier = verifier,
                Pbkdf2Iterations = iterations,
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

        var iterations = dto.Pbkdf2Iterations > 0 ? dto.Pbkdf2Iterations : Pbkdf2Iterations;
        await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, dto.PasswordSalt).ConfigureAwait(false);
        await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, dto.PasswordVerifier).ConfigureAwait(false);
        await SetStoredPbkdf2IterationsAsync(iterations).ConfigureAwait(false);
        SecureStorage.Default.Remove(BiometricKeyStorageKey);
        _encryptionKey = null;

        var vaultFile = await CreateVaultFileContentAsync(cipher, cancellationToken).ConfigureAwait(false);

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteVaultFileInternalAsync(vaultFile.RawContent, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }

        ClearStoredEntryCount();
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

        var importedContent = ParseVaultFile(payload);

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteVaultFileInternalAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }

        if (importedContent.Cipher.Length == 0)
        {
            UpdateStoredEntryCount(0);
        }
        else
        {
            _ = await TryGetEntryCountAsync(importedContent, cancellationToken).ConfigureAwait(false);
        }

        await UpdatePasswordMetadataAsync(importedContent).ConfigureAwait(false);
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

        var status = await GetSyncStatusAsync(cancellationToken).ConfigureAwait(false);
        status.NextAutoSyncUtc = null;

        if (!configuration.IsEnabled || !configuration.AutoSyncEnabled)
        {
            await SaveSyncStatusAsync(status).ConfigureAwait(false);
            return;
        }

        if (string.IsNullOrWhiteSpace(configuration.ProviderKey) || !_syncProviders.TryGetValue(configuration.ProviderKey, out var provider))
        {
            await SaveSyncStatusAsync(status).ConfigureAwait(false);
            return;
        }

        if (!provider.SupportsAutomaticSync)
        {
            await SaveSyncStatusAsync(status).ConfigureAwait(false);
            return;
        }

        if (!await provider.IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            await SaveSyncStatusAsync(status).ConfigureAwait(false);
            return;
        }

        status.NextAutoSyncUtc = DateTimeOffset.UtcNow.Add(DefaultAutoSyncInterval);
        await SaveSyncStatusAsync(status).ConfigureAwait(false);

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
            status.LastDownloadedEntries = result.DownloadedEntries;
            status.LastUploadedEntries = result.UploadedEntries;
        }
        else if (result.Operation == VaultSyncOperation.Error)
        {
            status.LastError = result.ErrorMessage;
        }
        else
        {
            status.LastError = result.ErrorMessage;
            if (result.Operation is VaultSyncOperation.Disabled or VaultSyncOperation.NoProvider)
            {
                status.LastDownloadedEntries = null;
                status.LastUploadedEntries = null;
            }
        }

        status.NextAutoSyncUtc = configuration.IsEnabled && configuration.AutoSyncEnabled
            ? DateTimeOffset.UtcNow.Add(DefaultAutoSyncInterval)
            : null;

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

    private void TriggerImmediateSyncIfEnabled(bool preferDownload = false)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                var configuration = await GetSyncConfigurationAsync().ConfigureAwait(false);
                if (!configuration.IsEnabled
                    || string.IsNullOrWhiteSpace(configuration.ProviderKey)
                    || !_syncProviders.TryGetValue(configuration.ProviderKey, out var provider))
                {
                    return;
                }

                if (!await provider.IsConfiguredAsync(configuration).ConfigureAwait(false))
                {
                    return;
                }

                if (RequiresRemotePassword(configuration.ProviderKey) && !IsUnlocked)
                {
                    return;
                }

                if (RequiresRemotePassword(configuration.ProviderKey)
                    && !await HasRemotePasswordAsync(configuration.ProviderKey).ConfigureAwait(false))
                {
                    return;
                }

                await SynchronizeAsync(preferDownload).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch
            {
                // Synchronisationsfehler werden bereits über den Status gemeldet.
            }
        });
    }

    private async Task<(byte[] Payload, VaultSyncRemoteState LocalState)> PrepareSyncPayloadAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken)
    {
        var providerKey = configuration.ProviderKey;
        if (!RequiresRemotePassword(providerKey))
        {
            var rawPayload = await ReadEncryptedFileAsync(cancellationToken).ConfigureAwait(false);
            var state = CreateLocalRemoteState(rawPayload);
            return (rawPayload, state);
        }

        var remotePassword = await GetRemotePasswordAsync(providerKey, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(remotePassword))
        {
            throw new InvalidOperationException("Für die ausgewählte Synchronisation ist ein Remote-Passwort erforderlich. Bitte lege in den Einstellungen eines fest.");
        }

        var remotePayload = await CreateRemotePackageAsync(remotePassword, cancellationToken).ConfigureAwait(false);
        var remoteState = CreateLocalRemoteState(remotePayload);
        return (remotePayload, remoteState);
    }

    private async Task<RemoteVaultSnapshotDto> ConvertRemotePayloadToLocalAsync(string? providerKey, byte[] payload, CancellationToken cancellationToken)
    {
        if (!RequiresRemotePassword(providerKey))
        {
            throw new InvalidOperationException("Der ausgewählte Synchronisationsanbieter unterstützt keine Remote-Snapshots.");
        }

        if (payload.Length == 0)
        {
            return new RemoteVaultSnapshotDto();
        }

        if (!IsRemotePackagePayload(payload))
        {
            throw new InvalidOperationException("Die entfernten Tresordaten haben ein unbekanntes Format.");
        }

        var remotePassword = await GetRemotePasswordAsync(providerKey, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(remotePassword))
        {
            throw new InvalidOperationException("Für die ausgewählte Synchronisation ist ein Remote-Passwort erforderlich. Bitte lege in den Einstellungen eines fest.");
        }

        return RemoteVaultPackageHelper.DecryptPackage(payload, remotePassword, Pbkdf2Iterations, KeySizeBytes, _jsonOptions);
    }

    private async Task<RemoteVaultSnapshotDto> CreateRemoteSnapshotAsync(CancellationToken cancellationToken)
    {
        EnsureUnlocked();
        var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
        var dtoList = entries
            .OrderBy(e => e.DisplayCategory, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(e => e.Label, StringComparer.CurrentCultureIgnoreCase)
            .Select(PasswordVaultEntryDto.FromModel)
            .ToList();

        return new RemoteVaultSnapshotDto
        {
            Entries = dtoList,
            ExportedAt = DateTimeOffset.UtcNow
        };
    }

    private async Task<int> MergeRemoteEntriesAsync(RemoteVaultSnapshotDto snapshot, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var remoteEntries = snapshot.Entries ?? new List<PasswordVaultEntryDto>();
        var localEntries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
        var merged = RemoteVaultEntryMerger.MergeInPlace(localEntries, remoteEntries);

        if (merged > 0)
        {
            await SaveEntriesInternalAsync(localEntries, cancellationToken).ConfigureAwait(false);
        }

        return merged;
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
        var vaultFile = await ReadVaultFileAsync(cancellationToken).ConfigureAwait(false);
        if (vaultFile.Cipher.Length == 0)
        {
            UpdateStoredEntryCount(0);
            return new List<PasswordVaultEntry>();
        }

        var decryptedBytes = await DecryptAsync(vaultFile.Cipher, cancellationToken).ConfigureAwait(false);
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
        var vaultFile = await CreateVaultFileContentAsync(encrypted, cancellationToken).ConfigureAwait(false);

        await WriteVaultFileInternalAsync(vaultFile.RawContent, cancellationToken).ConfigureAwait(false);
        UpdateStoredEntryCount(ordered.Count);
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
        if (!File.Exists(_vaultFilePath))
        {
            return VaultFileContent.Empty;
        }

        var rawContent = await File.ReadAllBytesAsync(_vaultFilePath, cancellationToken).ConfigureAwait(false);
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
            // Nicht im JSON-Format gespeichert.
        }
        catch (JsonException)
        {
            // Nicht im JSON-Format gespeichert.
        }
        catch (FormatException)
        {
            // Ungültiges Cipher-Format.
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
        await File.WriteAllBytesAsync(_vaultFilePath, rawContent, cancellationToken).ConfigureAwait(false);
    }

    private async Task<int?> TryGetLocalEntryCountAsync(CancellationToken cancellationToken)
    {
        try
        {
            var content = await ReadVaultFileAsync(cancellationToken).ConfigureAwait(false);
            return await TryGetEntryCountAsync(content, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private async Task<int?> TryGetEntryCountAsync(VaultFileContent content, CancellationToken cancellationToken)
    {
        if (content.Cipher.Length == 0)
        {
            UpdateStoredEntryCount(0);
            return 0;
        }

        try
        {
            var decrypted = await DecryptAsync(content.Cipher, cancellationToken).ConfigureAwait(false);
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

    private async Task<string?> GetRemotePasswordAsync(string? providerKey, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            return null;
        }

        var key = NormalizeRemoteProviderKey(providerKey);
        return await SecureStorage.Default.GetAsync(GetRemotePasswordStorageKey(key)).ConfigureAwait(false);
    }

    private async Task<byte[]> CreateRemotePackageAsync(string password, CancellationToken cancellationToken)
    {
        var snapshot = await CreateRemoteSnapshotAsync(cancellationToken).ConfigureAwait(false);
        var iterations = await GetStoredPbkdf2IterationsAsync().ConfigureAwait(false);
        return RemoteVaultPackageHelper.CreatePackage(snapshot, password, iterations, SaltSizeBytes, KeySizeBytes, _jsonOptions);
    }

    private async Task EnsurePasswordMetadataAsync(CancellationToken cancellationToken)
    {
        var salt = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey).ConfigureAwait(false);
        var verifier = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey).ConfigureAwait(false);

        var iterationsValue = await SecureStorage.Default.GetAsync(PasswordIterationsStorageKey).ConfigureAwait(false);
        var hasIterations = int.TryParse(iterationsValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var storedIterations) && storedIterations > 0;

        if (!string.IsNullOrEmpty(salt) && !string.IsNullOrEmpty(verifier) && hasIterations)
        {
            return;
        }

        var vaultFile = await ReadVaultFileAsync(cancellationToken).ConfigureAwait(false);
        var iterations = vaultFile.Pbkdf2Iterations.HasValue && vaultFile.Pbkdf2Iterations.Value > 0
            ? vaultFile.Pbkdf2Iterations.Value
            : Pbkdf2Iterations;

        if (!string.IsNullOrEmpty(salt) && !string.IsNullOrEmpty(verifier) && !hasIterations)
        {
            await SetStoredPbkdf2IterationsAsync(iterations).ConfigureAwait(false);
            return;
        }

        if (string.IsNullOrWhiteSpace(vaultFile.PasswordSalt) || string.IsNullOrWhiteSpace(vaultFile.PasswordVerifier))
        {
            if (!hasIterations)
            {
                await SetStoredPbkdf2IterationsAsync(Pbkdf2Iterations).ConfigureAwait(false);
            }
            return;
        }

        await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, vaultFile.PasswordSalt!).ConfigureAwait(false);
        await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, vaultFile.PasswordVerifier!).ConfigureAwait(false);
        await SetStoredPbkdf2IterationsAsync(iterations).ConfigureAwait(false);
        SecureStorage.Default.Remove(BiometricKeyStorageKey);
    }

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

    private static bool IsRemotePackagePayload(byte[] payload)
    {
        try
        {
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!root.TryGetProperty("cipherText", out _))
            {
                return false;
            }

            if (root.TryGetProperty("passwordSalt", out _))
            {
                return false;
            }

            return root.TryGetProperty("salt", out _);
        }
        catch (JsonException)
        {
            return false;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
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

    private static string NormalizeRemoteProviderKey(string providerKey)
        => providerKey.Trim().ToUpperInvariant();

    private static string GetRemotePasswordStorageKey(string normalizedProviderKey)
        => RemotePasswordStoragePrefix + normalizedProviderKey;

    private static bool RequiresRemotePassword(string? providerKey)
        => string.Equals(providerKey, GoogleDriveVaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase)
            || string.Equals(providerKey, FileSystemVaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase);

}
