using PasswordPhraseProducer.Updates;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OtpNet;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Security.Otp;
using Password_Phrase_Producer.Services.Synchronization;
using Password_Phrase_Producer.Services.Storage;
using Microsoft.Maui.ApplicationModel;

namespace Password_Phrase_Producer.Services.Security;

public class TotpService
{
    private const string TotpFileName = "totp_data.json.enc";
    private readonly string _totpFilePath;
    private readonly TotpEncryptionService _encryptionService;
    private readonly Services.Vault.VaultMergeService _vaultMergeService;
    private readonly ISynchronizationService _syncService;
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly SemaphoreSlim _syncLock = new(1, 1);

    public event EventHandler? EntriesChanged;

    public bool IsUnlocked => _encryptionService.IsUnlocked;
    public bool HasPassword => _encryptionService.HasPassword;


    public TotpService(
        TotpEncryptionService encryptionService,
        Services.Vault.VaultMergeService vaultMergeService,
        ISynchronizationService syncService)
    {
        _encryptionService = encryptionService;
        _vaultMergeService = vaultMergeService;
        _syncService = syncService;
        _totpFilePath = Path.Combine(FileSystem.AppDataDirectory, TotpFileName);
    }

    private void EnsureUnlocked()
    {
        if (!_encryptionService.IsUnlocked)
        {
            throw new InvalidOperationException("Der Authenticator ist gesperrt.");
        }
    }

    public async Task<List<TotpEntry>> GetEntriesAsync(CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (!_encryptionService.IsUnlocked)
            {
                 return new List<TotpEntry>();
            }
            var generation = _encryptionService.LockGeneration;

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                if (!_encryptionService.IsUnlocked || generation != _encryptionService.LockGeneration)
                {
                    foreach (var entry in entries)
                    {
                        if (entry.Secret is { } secret) CryptographicOperations.ZeroMemory(secret);
                        entry.Secret = null;
                    }
                    return new List<TotpEntry>();
                }
                foreach (var entry in entries.Where(e => e.IsDeleted))
                {
                    if (entry.Secret is { } secret) CryptographicOperations.ZeroMemory(secret);
                    entry.Secret = null;
                }
                return entries.Where(e => !e.IsDeleted).ToList();
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

    public async Task AddOrUpdateEntryAsync(TotpEntry entry, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            ArgumentNullException.ThrowIfNull(entry);
            EnsureUnlocked();

            await MutateEntriesAsync(entries =>
            {
                entry.ModifiedAt = DateTimeOffset.UtcNow;
                entry.IsDeleted = false; // Restore if it was deleted

                var existingIndex = entries.FindIndex(e => e.Id == entry.Id);
                if (existingIndex >= 0)
                {
                    entries[existingIndex] = entry;
                }
                else
                {
                    entries.Add(entry);
                }

                return true;
            }, cancellationToken).ConfigureAwait(false);

            EntriesChanged?.Invoke(this, EventArgs.Empty);
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

            await MutateEntriesAsync(entries =>
            {
                var entry = entries.FirstOrDefault(e => e.Id == entryId);
                if (entry is null)
                {
                    return false;
                }

                // Soft delete
                entry.IsDeleted = true;
                entry.ModifiedAt = DateTimeOffset.UtcNow;
                return true;
            }, cancellationToken).ConfigureAwait(false);

            EntriesChanged?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    /// <summary>
    /// Imports scanned accounts (otpauth:// or Google Authenticator export) in one step, so a
    /// large export is saved and synchronized only once. Accounts that already exist with the
    /// same secret and settings are skipped, unsupported ones (HOTP, MD5) are only counted.
    /// </summary>
    public async Task<TotpImportResult> ImportAccountsAsync(IEnumerable<OtpAccount> accounts, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            ArgumentNullException.ThrowIfNull(accounts);
            EnsureUnlocked();

            var accountList = accounts.ToList();
            var unsupported = accountList.Count(a => !a.IsSupported);
            var candidates = accountList.Where(a => a.IsSupported).Select(ToTotpEntry).ToList();
            var added = new List<TotpEntry>();
            var duplicates = 0;

            if (candidates.Count > 0)
            {
                await MutateEntriesAsync(entries =>
                {
                    var existing = entries.Where(e => !e.IsDeleted).ToList();
                    foreach (var candidate in candidates)
                    {
                        if (existing.Any(e => GeneratesSameCodes(e, candidate)))
                        {
                            duplicates++;
                            continue;
                        }

                        candidate.ModifiedAt = DateTimeOffset.UtcNow;
                        entries.Add(candidate);
                        existing.Add(candidate);
                        added.Add(candidate);
                    }

                    return added.Count > 0;
                }, cancellationToken).ConfigureAwait(false);
            }

            if (added.Count > 0)
            {
                EntriesChanged?.Invoke(this, EventArgs.Empty);
            }

            return new TotpImportResult(added, duplicates, unsupported);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    private static TotpEntry ToTotpEntry(OtpAccount account) => new()
    {
        Issuer = account.Issuer,
        AccountName = string.IsNullOrWhiteSpace(account.AccountName) ? "Unbenannt" : account.AccountName,
        Secret = account.Secret,
        Algorithm = account.Algorithm switch
        {
            OtpHashAlgorithm.Sha256 => TotpAlgorithm.Sha256,
            OtpHashAlgorithm.Sha512 => TotpAlgorithm.Sha512,
            _ => TotpAlgorithm.Sha1
        },
        Digits = account.Digits,
        Period = account.Period
    };

    private static bool GeneratesSameCodes(TotpEntry a, TotpEntry b)
        => a.Algorithm == b.Algorithm
           && a.Digits == b.Digits
           && a.Period == b.Period
           && a.Secret is not null
           && b.Secret is not null
           && a.Secret.AsSpan().SequenceEqual(b.Secret);

    /// <summary>
    /// Loads the entries, merges read-only sync data, applies <paramref name="mutate"/> and, if it
    /// reports a change, synchronizes and saves the result once.
    /// </summary>
    private async Task MutateEntriesAsync(Func<List<TotpEntry>, bool> mutate, CancellationToken cancellationToken)
    {
        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            var isSyncConfigured = await _syncService.IsConfiguredAsync().ConfigureAwait(false);
            var isReadOnlySync = isSyncConfigured && await IsReadOnlySyncAsync().ConfigureAwait(false);

            if (isReadOnlySync)
            {
                await MergeFromSyncReadOnlyAsync(entries, cancellationToken).ConfigureAwait(false);
            }

            if (!mutate(entries))
            {
                return;
            }

            if (isSyncConfigured)
            {
                try
                {
                    if (!isReadOnlySync)
                    {
                        await _syncService.SyncAuthenticatorAsync(entries, cancellationToken).ConfigureAwait(false);
                    }
                    Preferences.Set("AuthenticatorLastSync", DateTime.Now);
                }
                catch (Exception ex)
                {
                    if (!isReadOnlySync)
                    {
                         MainThread.BeginInvokeOnMainThread(async () =>
                         {
                             await Application.Current.MainPage.DisplayAlert("Sync Error", $"Fehler beim Synchronisieren (Auth): {ex.Message}", "OK");
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
    }

    public TotpCode? GenerateCode(TotpEntry entry)
    {
        if (!_encryptionService.IsUnlocked || entry.Secret == null || entry.Secret.Length == 0)
        {
            return null;
        }

        try
        {
            var mode = entry.Algorithm switch
            {
                TotpAlgorithm.Sha256 => OtpHashMode.Sha256,
                TotpAlgorithm.Sha512 => OtpHashMode.Sha512,
                _ => OtpHashMode.Sha1
            };

            var totp = new Totp(entry.Secret, step: entry.Period, mode: mode, totpSize: entry.Digits);
            var code = totp.ComputeTotp();
            var remaining = totp.RemainingSeconds();

            return new TotpCode(code, remaining, entry.Period);
        }
        catch
        {
            return null;
        }
    }

    private async Task<List<TotpEntry>> LoadEntriesInternalAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_totpFilePath))
        {
            return new List<TotpEntry>();
        }

        var encryptedBytes = await File.ReadAllBytesAsync(_totpFilePath, cancellationToken).ConfigureAwait(false);
        if (encryptedBytes.Length == 0)
        {
            throw new InvalidDataException("Die vorhandene Authenticator-Datei ist leer.");
        }

        byte[]? decryptedBytes = null;
        try
        {
            decryptedBytes = _encryptionService.Decrypt(encryptedBytes);

            if (decryptedBytes.Length == 0)
            {
                throw new InvalidDataException("Die Authenticator-Datei enthält keinen gültigen Snapshot.");
            }

            try
            {
                var snapshot = JsonSerializer.Deserialize<TotpSnapshotDto>(decryptedBytes, _jsonOptions);
                if (snapshot?.Entries is null)
                    throw new InvalidDataException("Die Authenticator-Datei enthält keine Einträge-Liste.");
                return snapshot.Entries.Select(e => e.ToModel()).ToList();
            }
            catch (Exception ex)
            {
                 throw new InvalidDataException("Die Authenticator-Datei ist beschädigt.", ex);
            }
        }
        catch (Exception ex) when (ex is not InvalidDataException)
        {
            // Decryption failed (or File read error handled above)
            throw new InvalidDataException("Fehler beim Entschlüsseln oder Lesen der Authenticator-Daten.", ex);
        }
        finally
        {
            if (decryptedBytes is not null)
            {
                // Sensible Daten aus dem Speicher löschen
                Array.Clear(decryptedBytes);
            }
        }
    }

    private async Task SaveEntriesInternalAsync(List<TotpEntry> entries, CancellationToken cancellationToken)
    {
        var dtos = entries.Select(TotpEntryDto.FromModel).ToList();
        var snapshot = new TotpSnapshotDto
        {
            Entries = dtos,
            ExportedAt = DateTimeOffset.UtcNow
        };

        var bytes = JsonSerializer.SerializeToUtf8Bytes(snapshot, _jsonOptions);

        try
        {
            var encryptedBytes = _encryptionService.Encrypt(bytes);

            Directory.CreateDirectory(Path.GetDirectoryName(_totpFilePath)!);
            await AtomicFile.WriteAsync(_totpFilePath, encryptedBytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Plain-Text JSON-Bytes aus dem Speicher löschen
            Array.Clear(bytes);
        }
    }

    /// <summary>
    /// Exports TOTP entries encrypted with a file password, similar to vault exports.
    /// </summary>
    public async Task<byte[]> ExportWithFilePasswordAsync(string filePassword, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            NewPasswordPolicy.Validate(filePassword, nameof(filePassword));
            EnsureUnlocked();

            const int KeySizeBytes = 32;
            const int SaltSizeBytes = 16;
            const int Pbkdf2Iterations = 600_000;

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                // 1. Klardaten auslesen
                var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                var dtos = entries.Select(TotpEntryDto.FromModel).ToList();

                var snapshot = new TotpSnapshotDto
                {
                    Entries = dtos,
                    ExportedAt = DateTimeOffset.UtcNow
                };

                var plainBytes = JsonSerializer.SerializeToUtf8Bytes(snapshot, _jsonOptions);

                try
                {
                    // 2. Mit Datei-Passwort verschlüsseln (neue Salt/Key für Export)
                    var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
                    var key = DeriveKey(filePassword, salt, Pbkdf2Iterations);
                    try
                    {
                        var encrypted = EncryptWithKey(plainBytes, key);
                        var verifier = CreateVerifier(key);

                        // 3. Format: { salt, verifier, iterations, cipherText }
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
                    // Plain-Text Daten aus dem Speicher löschen
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

    private static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        const int KeySizeBytes = 32;
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(KeySizeBytes);
    }

    private static byte[] CreateVerifier(byte[] key)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(key);
    }

    public async Task ImportWithFilePasswordAsync(Stream stream, string filePassword, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            ArgumentNullException.ThrowIfNull(stream);
            ArgumentException.ThrowIfNullOrWhiteSpace(filePassword);
            EnsureUnlocked();

            // 1. Datei lesen und parsen
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
                // 3. Klardaten in Tresor einfügen
                var snapshot = JsonSerializer.Deserialize<TotpSnapshotDto>(plainBytes, _jsonOptions)
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

                EntriesChanged?.Invoke(this, EventArgs.Empty);
            }
            finally
            {
                // Plain-Text Daten aus dem Speicher löschen
                Array.Clear(plainBytes);
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    private static byte[] DecryptWithKey(byte[] data, byte[] key)
    {
        const int nonceLength = 12;
        const int tagLength = 16;

        if (data.Length < nonceLength + tagLength)
        {
            throw new InvalidDataException("Der Chiffretext der Authenticator-Sicherung ist unvollständig.");
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

    public async Task<List<TotpEntry>> GetEntriesForExportAsync(CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            EnsureUnlocked();

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
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

    public async Task<Services.Vault.MergeResult<TotpEntry>> MergeEntriesAsync(
        IList<TotpEntry> incomingEntries,
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
                var result = _vaultMergeService.MergeEntries(existingEntries, incomingEntries);

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
            var backup = JsonSerializer.Deserialize<Models.AuthenticatorBackupDto>(json, _jsonOptions)
                         ?? throw new InvalidOperationException("Ungültiges Backup-Format.");

            var incomingEntries = backup.Entries.Select(dto => dto.ToModel()).ToList();
            await MergeEntriesAsync(incomingEntries, cancellationToken).ConfigureAwait(false);

            EntriesChanged?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task SyncAfterUnlockAsync(CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (!await _syncService.IsConfiguredAsync().ConfigureAwait(false)) return;

            EnsureUnlocked();
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
                    await _syncService.SyncAuthenticatorAsync(entries, cancellationToken).ConfigureAwait(false);
                }
                Preferences.Set("AuthenticatorLastSync", DateTime.Now);
                await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Sync failed
            }
            finally
            {
                _syncLock.Release();
            }
            EntriesChanged?.Invoke(this, EventArgs.Empty);
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
        return mode == SyncAccessMode.ReadMerge;
    }

    private async Task MergeFromSyncReadOnlyAsync(IList<TotpEntry> entries, CancellationToken cancellationToken)
    {
        var result = await _syncService.GetMergedAuthenticatorReadOnlyAsync(entries, cancellationToken).ConfigureAwait(false);
        entries.Clear();
        foreach (var mergedEntry in result.MergedEntries)
        {
            entries.Add(mergedEntry);
        }
    }

    public async Task LoadFromSyncAsync(CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (!await _syncService.IsConfiguredAsync().ConfigureAwait(false)) return;

            EnsureUnlocked();
            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
                var result = await _syncService.GetMergedAuthenticatorReadOnlyAsync(entries, cancellationToken).ConfigureAwait(false);
                Preferences.Set("AuthenticatorLastSync", DateTime.Now);
                await SaveEntriesInternalAsync(result.MergedEntries, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                // Sync failed
            }
            finally
            {
                _syncLock.Release();
            }

            EntriesChanged?.Invoke(this, EventArgs.Empty);
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
                // Delete TOTP data file
                if (File.Exists(_totpFilePath))
                {
                    File.Delete(_totpFilePath);
                }

                // Reset encryption service (clears password and key file)
                await _encryptionService.ResetAsync().ConfigureAwait(false);
            }
            finally
            {
                _syncLock.Release();
            }

            EntriesChanged?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }
}

public record TotpCode(string Code, int RemainingSeconds, int Period);

public sealed record TotpImportResult(IReadOnlyList<TotpEntry> Added, int Duplicates, int Unsupported);
