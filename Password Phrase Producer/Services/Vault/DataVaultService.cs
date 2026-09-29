using PasswordPhraseProducer.Updates;
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
using Microsoft.Maui.Controls;
using Microsoft.Maui.Storage;
using Microsoft.Maui.ApplicationModel;
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
    private const int Pbkdf2Iterations = 600_000;
    private const int LegacyPbkdf2Iterations = 200_000;
    private const int VaultFileFormatVersion = 1;

    private const string LastEntryCountStorageKey = "DataVaultLastEntryCount";

    private readonly SemaphoreSlim _syncLock = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private readonly IBiometricAuthenticationService _biometricService;
    private readonly IUnlockAttemptGate _attemptGate;
    private readonly ISecureFileService _secureFileService;
    private readonly VaultMergeService _vaultMergeService;
    private readonly Services.Synchronization.ISynchronizationService _syncService;
    private readonly string _vaultFilePath;
    private readonly object _keyStateLock = new();
    private long _lockGeneration;
    private byte[]? _encryptionKey;
    private PasswordMetadata? _activePasswordMetadata;

    public DataVaultService(
        IBiometricAuthenticationService biometricService,
        ISecureFileService secureFileService,
        VaultMergeService vaultMergeService,
        Services.Synchronization.ISynchronizationService syncService,
        IUnlockAttemptGate? attemptGate = null)
    {
        _biometricService = biometricService;
        _secureFileService = secureFileService;
        _vaultMergeService = vaultMergeService;
        _syncService = syncService;
        _attemptGate = attemptGate ?? new UnlockAttemptGate(new SecureUnlockAttemptStore());
        _attemptGate.LockedOut += access => { if (access == ProtectedAccess.DataVault) Lock(); };
        _vaultFilePath = Path.Combine(FileSystem.AppDataDirectory, VaultFileName);
    }

    public bool IsUnlocked { get { lock (_keyStateLock) return _encryptionKey is not null; } }

    public event EventHandler? Locked;

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
        lock (_keyStateLock)
        {
            _lockGeneration++;
            if (_encryptionKey is not null) CryptographicOperations.ZeroMemory(_encryptionKey);
            _encryptionKey = null;
            _activePasswordMetadata = null;
        }
        Locked?.Invoke(this, EventArgs.Empty);
    }

    public async Task SetMasterPasswordAsync(string password, bool enableBiometrics, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        long generation;
        lock (_keyStateLock) generation = _lockGeneration;
        try
        {
            NewPasswordPolicy.Validate(password, nameof(password));

            StartupDataGuard.RequireNewStore(_vaultFilePath);

            var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
            var key = DeriveKey(password, salt, Pbkdf2Iterations);
            var verifier = CreateVerifier(key);

            await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, Convert.ToBase64String(salt)).ConfigureAwait(false);
            await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, Convert.ToBase64String(verifier)).ConfigureAwait(false);
            await SetStoredPbkdf2IterationsAsync(Pbkdf2Iterations).ConfigureAwait(false);

            lock (_keyStateLock)
            {
                if (_lockGeneration != generation)
                {
                    CryptographicOperations.ZeroMemory(key);
                    throw new OperationCanceledException("Der Tresor wurde während der Einrichtung gesperrt.");
                }
                _encryptionKey = key;
                _activePasswordMetadata = new PasswordMetadata(Convert.ToBase64String(salt), Convert.ToBase64String(verifier), Pbkdf2Iterations);
            }
            UpdateStoredEntryCount(0);
            await _attemptGate.ResetAsync(ProtectedAccess.DataVault).ConfigureAwait(false);

            if (enableBiometrics)
            {
                 await SetBiometricUnlockAsync(true, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                SecureStorage.Default.Remove(BiometricKeyStorageKey);
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<bool> UnlockAsync(string password, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            return await _attemptGate.RunPasswordAsync(ProtectedAccess.DataVault,
                () => UnlockInternalAsync(password, syncAfterUnlock: true, cancellationToken)).ConfigureAwait(false);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<bool> UnlockWithoutSyncAsync(string password, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            return await _attemptGate.RunPasswordAsync(ProtectedAccess.DataVault,
                () => UnlockInternalAsync(password, syncAfterUnlock: false, cancellationToken)).ConfigureAwait(false);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    private async Task<bool> UnlockInternalAsync(string password, bool syncAfterUnlock, CancellationToken cancellationToken)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        long generation;
        lock (_keyStateLock) generation = _lockGeneration;
        byte[]? key = null;
        var acceptedKey = false;
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(password);

            var storedMetadata = await GetPasswordMetadataAsync(cancellationToken).ConfigureAwait(false);
            var vaultFile = await ReadVaultFileAsync(cancellationToken).ConfigureAwait(false);
            var fileMetadata = !string.IsNullOrWhiteSpace(vaultFile.PasswordSalt) &&
                               !string.IsNullOrWhiteSpace(vaultFile.PasswordVerifier)
                ? new PasswordMetadata(vaultFile.PasswordSalt, vaultFile.PasswordVerifier,
                    vaultFile.Pbkdf2Iterations.GetValueOrDefault(LegacyPbkdf2Iterations))
                : null;

            PasswordMetadata? selectedMetadata = null;
            foreach (var candidate in new[] { storedMetadata, fileMetadata }.OfType<PasswordMetadata>().Distinct())
            {
                if (string.IsNullOrEmpty(candidate.Salt) || string.IsNullOrEmpty(candidate.Verifier)) continue;
                byte[] candidateSalt;
                byte[] expectedVerifier;
                try
                {
                    candidateSalt = Convert.FromBase64String(candidate.Salt);
                    expectedVerifier = Convert.FromBase64String(candidate.Verifier);
                }
                catch (FormatException) { continue; }
                if (candidateSalt.Length != SaltSizeBytes || expectedVerifier.Length != 32 ||
                    candidate.Iterations is < 10_000 or > 1_000_000) continue;

                var candidateKey = DeriveKey(password, candidateSalt, candidate.Iterations);
                var verifier = CreateVerifier(candidateKey);
                if (CryptographicOperations.FixedTimeEquals(verifier, expectedVerifier))
                {
                    try
                    {
                        if (vaultFile.Cipher.Length > 0)
                            Array.Clear(DecryptWithKey(vaultFile.Cipher, candidateKey));
                        key = candidateKey;
                        selectedMetadata = candidate;
                        break;
                    }
                    catch (CryptographicException) { }
                }
                Array.Clear(candidateKey);
            }

            if (key is null || selectedMetadata is null) return false;

            if (vaultFile.RawContent.Length > 0 && fileMetadata != selectedMetadata)
            {
                var repaired = await CreateVaultFileContentAsync(vaultFile.Cipher, cancellationToken, selectedMetadata)
                    .ConfigureAwait(false);
                await WriteVaultFileInternalAsync(repaired.RawContent, cancellationToken).ConfigureAwait(false);
            }
            if (storedMetadata != selectedMetadata)
            {
                await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, selectedMetadata.Salt!).ConfigureAwait(false);
                await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, selectedMetadata.Verifier!).ConfigureAwait(false);
                await SetStoredPbkdf2IterationsAsync(selectedMetadata.Iterations).ConfigureAwait(false);
                SecureStorage.Default.Remove(BiometricKeyStorageKey);
            }

            lock (_keyStateLock)
            {
                if (_lockGeneration != generation)
                {
                    return false;
                }
                if (_encryptionKey is not null) CryptographicOperations.ZeroMemory(_encryptionKey);
                _encryptionKey = key;
                key = null;
                acceptedKey = true;
                _activePasswordMetadata = selectedMetadata;
            }

            if (syncAfterUnlock && await _syncService.IsConfiguredAsync().ConfigureAwait(false))
            {
                await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                    var isReadOnlySync = await IsReadOnlySyncAsync().ConfigureAwait(false);
                    if (isReadOnlySync)
                    {
                        await MergeFromSyncReadOnlyAsync(entries, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        await _syncService.SyncDataVaultAsync(entries, cancellationToken).ConfigureAwait(false);
                    }
                    Preferences.Set("DataVaultLastSync", DateTime.Now);
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
        catch
        {
            if (acceptedKey) Lock();
            dataOperation.Failed();
            throw;
        }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
        }
    }

    public async Task ChangeMasterPasswordAsync(string currentPassword, string newPassword, bool enableBiometrics, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        long generation;
        lock (_keyStateLock) generation = _lockGeneration;
        try
        {
            EnsureUnlocked();
            if (!await _attemptGate.RunPasswordAsync(ProtectedAccess.DataVault, () =>
                {
                    try { VerifyCurrentMasterPassword(currentPassword); return Task.FromResult(true); }
                    catch (UnauthorizedAccessException) { return Task.FromResult(false); }
                }).ConfigureAwait(false))
                throw new UnauthorizedAccessException("Das aktuelle Master-Passwort ist falsch oder der Tresor ist gesperrt.");
            NewPasswordPolicy.Validate(newPassword, nameof(newPassword));

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);

                var newSalt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
                byte[]? newKey = DeriveKey(newPassword, newSalt, Pbkdf2Iterations);
                var newVerifier = CreateVerifier(newKey);
                var newMetadata = new PasswordMetadata(Convert.ToBase64String(newSalt), Convert.ToBase64String(newVerifier), Pbkdf2Iterations);

                try
                {
                    await SaveEntriesInternalAsync(entries, cancellationToken, newMetadata, newKey)
                        .ConfigureAwait(false);
                    lock (_keyStateLock)
                    {
                        if (_lockGeneration == generation && _encryptionKey is not null)
                        {
                            CryptographicOperations.ZeroMemory(_encryptionKey);
                            _encryptionKey = newKey;
                            _activePasswordMetadata = newMetadata;
                            newKey = null;
                        }
                    }

                    await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, Convert.ToBase64String(newSalt)).ConfigureAwait(false);
                    await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, Convert.ToBase64String(newVerifier)).ConfigureAwait(false);
                    await SetStoredPbkdf2IterationsAsync(Pbkdf2Iterations).ConfigureAwait(false);

                    if (enableBiometrics && IsUnlocked)
                        await SetBiometricUnlockAsync(true, cancellationToken).ConfigureAwait(false);
                    else
                        SecureStorage.Default.Remove(BiometricKeyStorageKey);
                }
                finally
                {
                    if (newKey is not null) CryptographicOperations.ZeroMemory(newKey);
                }
            }
            finally
            {
                _syncLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public Task<bool> TryUnlockWithStoredKeyAsync(CancellationToken cancellationToken = default) =>
        _attemptGate.RunBiometricAsync(ProtectedAccess.DataVault,
            () => TryUnlockWithStoredKeyCoreAsync(cancellationToken));

    private async Task<bool> TryUnlockWithStoredKeyCoreAsync(CancellationToken cancellationToken)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        long generation;
        lock (_keyStateLock) generation = _lockGeneration;
        try
        {
            var storedKeyBase64 = await SecureStorage.Default.GetAsync(BiometricKeyStorageKey).ConfigureAwait(false);
            var metadata = await GetPasswordMetadataAsync(cancellationToken).ConfigureAwait(false);

            if (string.IsNullOrEmpty(storedKeyBase64) || string.IsNullOrEmpty(metadata.Verifier))
            {

                return false;
            }

            byte[]? key = null;
            var acceptedKey = false;
            try
            {
                var encryptedKey = Convert.FromBase64String(storedKeyBase64);
                key = await _biometricService.DecryptAsync(encryptedKey, cancellationToken).ConfigureAwait(false);

                var expectedVerifier = Convert.FromBase64String(metadata.Verifier);
                var actualVerifier = CreateVerifier(key);

                if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
                {
                    SecureStorage.Default.Remove(BiometricKeyStorageKey);
                    return false;
                }

                var vaultFile = await ReadVaultFileAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    if (vaultFile.Cipher.Length > 0)
                        Array.Clear(DecryptWithKey(vaultFile.Cipher, key));
                }
                catch (CryptographicException)
                {
                    SecureStorage.Default.Remove(BiometricKeyStorageKey);
                    return false;
                }
                if (vaultFile.RawContent.Length > 0 &&
                    (vaultFile.PasswordSalt != metadata.Salt || vaultFile.PasswordVerifier != metadata.Verifier ||
                     vaultFile.Pbkdf2Iterations != metadata.Iterations))
                {
                    var repaired = await CreateVaultFileContentAsync(vaultFile.Cipher, cancellationToken, metadata)
                        .ConfigureAwait(false);
                    await WriteVaultFileInternalAsync(repaired.RawContent, cancellationToken).ConfigureAwait(false);
                }

                lock (_keyStateLock)
                {
                    if (_lockGeneration != generation)
                    {
                        return false;
                    }
                    if (_encryptionKey is not null) CryptographicOperations.ZeroMemory(_encryptionKey);
                    _encryptionKey = key;
                    key = null;
                    acceptedKey = true;
                    _activePasswordMetadata = metadata;
                }

                if (await _syncService.IsConfiguredAsync().ConfigureAwait(false))
                {
                    await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
                    try
                    {
                        var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                        var isReadOnlySync = await IsReadOnlySyncAsync().ConfigureAwait(false);
                        if (isReadOnlySync)
                        {
                            await MergeFromSyncReadOnlyAsync(entries, cancellationToken).ConfigureAwait(false);
                        }
                        else
                        {
                            await _syncService.SyncDataVaultAsync(entries, cancellationToken).ConfigureAwait(false);
                        }
                        Preferences.Set("DataVaultLastSync", DateTime.Now);
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
            }
            catch (UnauthorizedAccessException)
            {
                if (acceptedKey) Lock();
                throw;
            }
            catch (Exception)
            {
                if (acceptedKey) Lock();
                 return false;
            }
            finally
            {
                if (key is not null) CryptographicOperations.ZeroMemory(key);
            }

            return true;
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task LoadFromSyncAsync(CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (!IsUnlocked) return;

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (!await _syncService.IsConfiguredAsync().ConfigureAwait(false))
                {
                    return;
                }

                var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                var result = await _syncService.GetMergedDataVaultReadOnlyAsync(entries, cancellationToken).ConfigureAwait(false);
                entries.Clear();
                foreach (var entry in result.MergedEntries)
                {
                    entries.Add(entry);
                }

                Preferences.Set("DataVaultLastSync", DateTime.Now);
                await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _syncLock.Release();
            }

            MessagingCenter.Send(this, DataVaultMessages.EntriesChanged);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task SetBiometricUnlockAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        long generation;
        lock (_keyStateLock) generation = _lockGeneration;
        try
        {
            if (!IsUnlocked)
            {
                throw new InvalidOperationException("Der Datentresor ist gesperrt.");
            }

            if (enabled)
            {
                var key = GetUnlockedKey();
                try
                {
                    var encrypted = await _biometricService.EncryptAsync(key, cancellationToken).ConfigureAwait(false);
                    bool stillActive;
                    lock (_keyStateLock)
                        stillActive = _lockGeneration == generation && _encryptionKey is not null &&
                                      CryptographicOperations.FixedTimeEquals(_encryptionKey, key);
                    if (!stillActive)
                    {
                        SecureStorage.Default.Remove(BiometricKeyStorageKey);
                        throw new OperationCanceledException("Der Datentresor wurde während der Biometrie-Einrichtung gesperrt.");
                    }
                    await SecureStorage.Default.SetAsync(BiometricKeyStorageKey, Convert.ToBase64String(encrypted)).ConfigureAwait(false);
                    lock (_keyStateLock)
                        stillActive = _lockGeneration == generation && _encryptionKey is not null &&
                                      CryptographicOperations.FixedTimeEquals(_encryptionKey, key);
                    if (!stillActive)
                    {
                        SecureStorage.Default.Remove(BiometricKeyStorageKey);
                        throw new OperationCanceledException("Der Datentresor wurde während der Biometrie-Einrichtung gesperrt.");
                    }
                }
                catch
                {
                     SecureStorage.Default.Remove(BiometricKeyStorageKey);
                     throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(key);
                }
            }
            else
            {
                SecureStorage.Default.Remove(BiometricKeyStorageKey);
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<IReadOnlyList<PasswordVaultEntry>> GetEntriesAsync(CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            EnsureUnlocked();
            long generation;
            lock (_keyStateLock) generation = _lockGeneration;

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                var visibleEntries = entries
                    .Where(e => !e.IsDeleted) // Filter out soft-deleted items
                    .OrderBy(e => e.DisplayCategory, StringComparer.CurrentCultureIgnoreCase)
                    .ThenBy(e => e.Label, StringComparer.CurrentCultureIgnoreCase)
                    .ToList();
                lock (_keyStateLock)
                    return _lockGeneration == generation && _encryptionKey is not null
                        ? visibleEntries : Array.Empty<PasswordVaultEntry>();
            }
            finally
            {
                _syncLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task AddOrUpdateEntryAsync(PasswordVaultEntry entry, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            ArgumentNullException.ThrowIfNull(entry);
            EnsureUnlocked();

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                var existingIndex = entries.FindIndex(e => e.Id == entry.Id);
                var isSyncConfigured = await _syncService.IsConfiguredAsync().ConfigureAwait(false);
                var isReadOnlySync = isSyncConfigured && await IsReadOnlySyncAsync().ConfigureAwait(false);

                if (isReadOnlySync)
                {
                    await MergeFromSyncReadOnlyAsync(entries, cancellationToken).ConfigureAwait(false);
                    existingIndex = entries.FindIndex(e => e.Id == entry.Id);
                }

                if (entry.Id == Guid.Empty)
                {
                    entry.Id = Guid.NewGuid();
                }

                entry.ModifiedAt = DateTimeOffset.UtcNow;
                entry.IsDeleted = false; // Ensure it's revived if it was deleted

                if (existingIndex >= 0)
                {
                    entries[existingIndex] = entry.Clone();
                }
                else
                {
                    entries.Add(entry.Clone());
                }

                if (isSyncConfigured)
                {
                    try
                    {
                        if (!isReadOnlySync)
                        {
                            await _syncService.SyncDataVaultAsync(entries, cancellationToken).ConfigureAwait(false);
                        }
                        Preferences.Set("DataVaultLastSync", DateTime.Now);
                    }
                    catch (Exception ex)
                    {
                        if (!isReadOnlySync)
                        {
                             MainThread.BeginInvokeOnMainThread(async () =>
                             {
                                 await Application.Current.MainPage.DisplayAlert("Sync Error", $"Fehler beim Synchronisieren (Data): {ex.Message}", "OK");
                             });
                        }
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
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task DeleteEntryAsync(Guid entryId, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            EnsureUnlocked();

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                var entry = entries.FirstOrDefault(e => e.Id == entryId);
                var isSyncConfigured = await _syncService.IsConfiguredAsync().ConfigureAwait(false);
                var isReadOnlySync = isSyncConfigured && await IsReadOnlySyncAsync().ConfigureAwait(false);

                if (isReadOnlySync)
                {
                    await MergeFromSyncReadOnlyAsync(entries, cancellationToken).ConfigureAwait(false);
                    entry = entries.FirstOrDefault(e => e.Id == entryId);
                }

                if (entry != null)
                {
                    // Soft delete
                    entry.IsDeleted = true;
                    entry.ModifiedAt = DateTimeOffset.UtcNow;

                    if (isSyncConfigured)
                    {
                        try
                        {
                            if (!isReadOnlySync)
                            {
                                await _syncService.SyncDataVaultAsync(entries, cancellationToken).ConfigureAwait(false);
                            }
                            Preferences.Set("DataVaultLastSync", DateTime.Now);
                        }
                        catch (Exception ex)
                        {
                            if (!isReadOnlySync)
                            {
                                 MainThread.BeginInvokeOnMainThread(async () =>
                                 {
                                     await Application.Current.MainPage.DisplayAlert("Sync Error", $"Fehler beim Synchronisieren (Data): {ex.Message}", "OK");
                                 });
                            }
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
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task SyncNowAsync(CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (!IsUnlocked) return;

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                if (await _syncService.IsConfiguredAsync().ConfigureAwait(false))
                {
                    var isReadOnlySync = await IsReadOnlySyncAsync().ConfigureAwait(false);
                    if (isReadOnlySync)
                    {
                        await MergeFromSyncReadOnlyAsync(entries, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        await _syncService.SyncDataVaultAsync(entries, cancellationToken).ConfigureAwait(false);
                    }
                    Preferences.Set("DataVaultLastSync", DateTime.Now);
                    await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                _syncLock.Release();
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    private async Task<bool> IsReadOnlySyncAsync()
    {
        var mode = await _syncService.GetAccessModeAsync().ConfigureAwait(false);
        return mode == Services.Synchronization.SyncAccessMode.ReadMerge;
    }

    private async Task MergeFromSyncReadOnlyAsync(IList<PasswordVaultEntry> entries, CancellationToken cancellationToken)
    {
        var result = await _syncService.GetMergedDataVaultReadOnlyAsync(entries, cancellationToken).ConfigureAwait(false);
        entries.Clear();
        foreach (var mergedEntry in result.MergedEntries)
        {
            entries.Add(mergedEntry);
        }
    }

    public async Task<byte[]> ExportWithFilePasswordAsync(string filePassword, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            NewPasswordPolicy.Validate(filePassword, nameof(filePassword));
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

                var plainBytes = JsonSerializer.SerializeToUtf8Bytes(snapshot, _jsonOptions);

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

                        return JsonSerializer.SerializeToUtf8Bytes(exportDto, _jsonOptions);
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
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task ImportWithFilePasswordAsync(Stream stream, string filePassword, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentException.ThrowIfNullOrWhiteSpace(filePassword);
            EnsureUnlocked();

            var json = await BackupInput.ReadJsonAsync(stream, cancellationToken).ConfigureAwait(false);
            var dto = JsonSerializer.Deserialize<PortableBackupDto>(json, _jsonOptions)
                      ?? throw new InvalidOperationException("Ungültiges Export-Format.");

            var validated = BackupInput.Validate(dto);
            var key = DeriveKey(filePassword, validated.Salt, dto.Iterations);
            byte[] plainBytes;
            try
            {
                var actualVerifier = CreateVerifier(key);
                if (!CryptographicOperations.FixedTimeEquals(validated.Verifier, actualVerifier))
                    throw new InvalidOperationException("Falsches Datei-Passwort.");
                plainBytes = DecryptWithKey(validated.Cipher, key);
            }
            finally
            {
                Array.Clear(key);
                Array.Clear(validated.Cipher);
            }

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
        catch
        {
            dataOperation.Failed();
            throw;
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
                throw new InvalidDataException("Die Datentresor-Datei enthält keinen gültigen Snapshot.");
            }

            var snapshot = JsonSerializer.Deserialize<PasswordVaultSnapshotDto>(decryptedBytes, _jsonOptions);

            if (snapshot?.Entries is null)
            {
                throw new InvalidDataException("Die Datentresor-Datei enthält keine Einträge-Liste.");
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

    private async Task SaveEntriesInternalAsync(IList<PasswordVaultEntry> entries, CancellationToken cancellationToken,
        PasswordMetadata? metadataOverride = null, byte[]? encryptionKeyOverride = null)
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

        var plainBytes = JsonSerializer.SerializeToUtf8Bytes(snapshot, _jsonOptions);
        try
        {
            var encrypted = encryptionKeyOverride is null
                ? await EncryptAsync(plainBytes, cancellationToken).ConfigureAwait(false)
                : EncryptWithKey(plainBytes, encryptionKeyOverride);
            var vaultFile = await CreateVaultFileContentAsync(encrypted, cancellationToken, metadataOverride).ConfigureAwait(false);

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
        try { return Task.FromResult(EncryptWithKey(data, key)); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken)
    {
        var key = GetUnlockedKey();
        try { return Task.FromResult(DecryptWithKey(data, key)); }
        finally { CryptographicOperations.ZeroMemory(key); }
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
        if (rawContent.Length == 0)
            throw new InvalidDataException("Die vorhandene Datentresor-Datei ist leer.");
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

                throw new InvalidDataException("Die Datentresor-Datei enthält keinen Chiffretext.");
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

    private Task<VaultFileContent> CreateVaultFileContentAsync(byte[] cipher, CancellationToken cancellationToken,
        PasswordMetadata? metadataOverride = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var metadata = metadataOverride ?? _activePasswordMetadata
            ?? throw new InvalidOperationException("Der Tresor muss vor dem Speichern entsperrt sein.");

        var dto = new EncryptedVaultFileDto
        {
            Version = VaultFileFormatVersion,
            CipherText = Convert.ToBase64String(cipher),
            PasswordSalt = metadata.Salt,
            PasswordVerifier = metadata.Verifier,
            Pbkdf2Iterations = metadata.Iterations
        };

        var rawContent = JsonSerializer.SerializeToUtf8Bytes(dto, _jsonOptions);
        return Task.FromResult(new VaultFileContent(cipher, metadata.Salt, metadata.Verifier, metadata.Iterations, rawContent));
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
                : LegacyPbkdf2Iterations;
            return new PasswordMetadata(vaultFile.PasswordSalt, vaultFile.PasswordVerifier, vaultIterations);
        }

        StartupDataGuard.RequireNewStore(_vaultFilePath);
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
            : LegacyPbkdf2Iterations;
        await SetStoredPbkdf2IterationsAsync(iterations).ConfigureAwait(false);
        SecureStorage.Default.Remove(BiometricKeyStorageKey);
    }

    private sealed record VaultFileContent(byte[] Cipher, string? PasswordSalt, string? PasswordVerifier, int? Pbkdf2Iterations, byte[] RawContent)
    {
        public static VaultFileContent Empty { get; } = new(Array.Empty<byte>(), null, null, null, Array.Empty<byte>());
    }

    internal byte[] GetUnlockedKey()
    {
        lock (_keyStateLock)
        {
            if (_encryptionKey is null)
                throw new InvalidOperationException("Der Datentresor ist gesperrt.");
            return _encryptionKey.ToArray();
        }
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
        if (int.TryParse(storedValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var iterations) &&
            iterations is >= 10_000 and <= 1_000_000)
        {
            return iterations;
        }

        return LegacyPbkdf2Iterations;
    }

    private static Task SetStoredPbkdf2IterationsAsync(int iterations)
    {
        var effective = iterations is >= 10_000 and <= 1_000_000 ? iterations : LegacyPbkdf2Iterations;
        return SecureStorage.Default.SetAsync(PasswordIterationsStorageKey, effective.ToString(CultureInfo.InvariantCulture));
    }

    private void VerifyCurrentMasterPassword(string currentPassword)
    {
        if (string.IsNullOrWhiteSpace(currentPassword))
            throw new UnauthorizedAccessException("Das aktuelle Master-Passwort ist erforderlich.");

        PasswordMetadata metadata;
        lock (_keyStateLock)
            metadata = _activePasswordMetadata ?? throw new InvalidOperationException("Der Datentresor ist gesperrt.");
        var salt = Convert.FromBase64String(metadata.Salt ?? string.Empty);
        if (salt.Length != SaltSizeBytes || metadata.Iterations is < 10_000 or > 1_000_000)
            throw new InvalidDataException("Ungültige Passwort-Metadaten.");

        var derived = DeriveKey(currentPassword, salt, metadata.Iterations);
        try
        {
            lock (_keyStateLock)
            {
                if (_encryptionKey is null || !CryptographicOperations.FixedTimeEquals(_encryptionKey, derived))
                    throw new UnauthorizedAccessException("Das aktuelle Master-Passwort ist falsch.");
            }
        }
        finally { CryptographicOperations.ZeroMemory(derived); }
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
            throw new InvalidDataException("Der Chiffretext der Datentresor-Datei ist unvollständig.");
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
        try
        {
            using var aes = new AesGcm(key, tagLength);
            aes.Decrypt(nonce, cipher, tag, plain);
            return plain;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plain);
            throw;
        }
    }

    public async Task<MergeResult<PasswordVaultEntry>> MergeEntriesAsync(
        IList<PasswordVaultEntry> incomingEntries,
        CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
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
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task RestoreBackupWithMergeAsync(Stream backupStream, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            ArgumentNullException.ThrowIfNull(backupStream);
            EnsureUnlocked();

            var json = await BackupInput.ReadJsonAsync(backupStream, cancellationToken).ConfigureAwait(false);
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
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task ResetVaultAsync(CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
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
                await _attemptGate.ResetAsync(ProtectedAccess.DataVault).ConfigureAwait(false);
            }
            finally
            {
                _syncLock.Release();
            }

            MessagingCenter.Send(this, DataVaultMessages.EntriesChanged);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }
}
