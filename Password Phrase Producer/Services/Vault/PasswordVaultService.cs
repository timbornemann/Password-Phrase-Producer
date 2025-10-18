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
    private const string KeyStorageKey = "PasswordVaultEncryptionKey";
    private const string VaultFileName = "vault.json.enc";

    private readonly SemaphoreSlim _syncLock = new(1, 1);
    private readonly SemaphoreSlim _keyLock = new(1, 1);
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

    public async Task EnsureInitializedAsync(CancellationToken cancellationToken = default)
    {
        _ = await GetKeyAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<PasswordVaultEntry>> GetEntriesAsync(CancellationToken cancellationToken = default)
    {
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
        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var encryptedPayload = await ReadEncryptedFileAsync(cancellationToken).ConfigureAwait(false);
            var key = await GetKeyAsync(cancellationToken).ConfigureAwait(false);

            var backup = new PasswordVaultBackupDto
            {
                EncryptionKey = Convert.ToBase64String(key),
                CipherText = Convert.ToBase64String(encryptedPayload),
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

        var key = Convert.FromBase64String(dto.EncryptionKey);
        var cipher = Convert.FromBase64String(dto.CipherText);

        await SetKeyAsync(key, cancellationToken).ConfigureAwait(false);

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
        var key = await GetKeyAsync(cancellationToken).ConfigureAwait(false);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[data.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(key);
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

        var key = await GetKeyAsync(cancellationToken).ConfigureAwait(false);
        var nonce = data.AsSpan(0, 12);
        var tag = data.AsSpan(data.Length - 16, 16);
        var cipher = data.AsSpan(12, data.Length - 28);
        var plain = new byte[cipher.Length];

        using var aes = new AesGcm(key);
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

    private async Task<byte[]> GetKeyAsync(CancellationToken cancellationToken)
    {
        if (_encryptionKey is not null)
        {
            return _encryptionKey;
        }

        await _keyLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_encryptionKey is null)
            {
                var storedKey = await SecureStorage.Default.GetAsync(KeyStorageKey).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(storedKey))
                {
                    _encryptionKey = Convert.FromBase64String(storedKey);
                }
                else
                {
                    var keyBytes = RandomNumberGenerator.GetBytes(32);
                    await SecureStorage.Default.SetAsync(KeyStorageKey, Convert.ToBase64String(keyBytes)).ConfigureAwait(false);
                    _encryptionKey = keyBytes;
                }
            }

            return _encryptionKey;
        }
        finally
        {
            _keyLock.Release();
        }
    }

    private async Task SetKeyAsync(byte[] key, CancellationToken cancellationToken)
    {
        await _keyLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _encryptionKey = key;
            await SecureStorage.Default.SetAsync(KeyStorageKey, Convert.ToBase64String(key)).ConfigureAwait(false);
        }
        finally
        {
            _keyLock.Release();
        }
    }
}
