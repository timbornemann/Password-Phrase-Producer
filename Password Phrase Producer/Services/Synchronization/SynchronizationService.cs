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
    private const int Iterations = 200_000;

    private readonly ISyncFileService _syncFileService;
    private readonly IAppLockService _appLockService;
    private readonly VaultMergeService _vaultMergeService;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private byte[]? _cachedCommonKey;
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public SynchronizationService(IAppLockService appLockService, VaultMergeService vaultMergeService, ISyncFileService syncFileService)
    {
        _appLockService = appLockService;
        _vaultMergeService = vaultMergeService;
        _syncFileService = syncFileService;
    }

    public async Task ConfigureAsync(string path, string password)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Path and password are required.");

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = await Task.Run(() => DeriveKey(password, salt, Iterations)).ConfigureAwait(false);
        var verifier = CreateVerifier(key);

        var header = new ExternalVaultHeader
        {
            Version = 1,
            Salt = Convert.ToBase64String(salt),
            Verifier = Convert.ToBase64String(verifier),
            Iterations = Iterations
        };

        if (await _syncFileService.ExistsAsync(path)) // Abstracted check
        {
            // We need to check if it has content (length > 0). ISyncFileService abstraction doesn't have Length?
            // Open stream to check.
            using var stream = await _syncFileService.OpenReadAsync(path);
            var length = stream.Length;
            stream.Close();

            if (length > 0)
            {
                 try 
                 {
                    var existingHeader = await ReadHeaderAsync(path);
                    if (existingHeader != null)
                    {
                        var existingSalt = Convert.FromBase64String(existingHeader.Salt);
                        var existingKey = await Task.Run(() => DeriveKey(password, existingSalt, existingHeader.Iterations)).ConfigureAwait(false);
                        var expectedVerifier = Convert.FromBase64String(existingHeader.Verifier);
                        var actualVerifier = CreateVerifier(existingKey);
                        
                        if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
                        {
                             throw new InvalidOperationException("Das angegebene Passwort stimmt nicht mit der existierenden Sync-Datei überein.");
                        }
                        
                        key = existingKey; 
                        header = existingHeader; 
                    }
                 }
                 catch (Exception ex) when (ex is not InvalidOperationException)
                 {
                    // If parsing fails for any reason (e.g. legacy format or garbage), treat as invalid? 
                    // Or ask user to overwrite? For now, throw is safer to avoid accidental data loss.
                    throw new InvalidOperationException("Die Datei existiert bereits, ist aber keine gültige oder lesbare Sync-Datei.", ex);
                 }
            }
            else
            {
                // File exists but is empty -> Initialize it
                var content = new ExternalVaultContent();
                await WriteVaultFileAsync(path, header, content, key);
            }
        }
        else
        {
            var content = new ExternalVaultContent();
            await WriteVaultFileAsync(path, header, content, key);
        }

        Preferences.Set(SyncPathKey, path);
        if (_appLockService.IsUnlocked)
        {
            var encryptedKey = _appLockService.EncryptWithMasterKey(key);
            await SecureStorage.Default.SetAsync(SyncKeyStorageKey, Convert.ToBase64String(encryptedKey));
            _cachedCommonKey = key;
        }
        else
        {
             throw new InvalidOperationException("App must be unlocked to configure sync.");
        }
    }

    public Task ClearConfigurationAsync()
    {
        Preferences.Remove(SyncPathKey);
        Preferences.Remove(SyncAccessModeKey);
        SecureStorage.Default.Remove(SyncKeyStorageKey);
        _cachedCommonKey = null;
        return Task.CompletedTask;
    }

    public Task<SyncAccessMode> GetAccessModeAsync()
    {
        var storedValue = Preferences.Get(SyncAccessModeKey, nameof(SyncAccessMode.ReadWrite));
        return Task.FromResult(Enum.TryParse(storedValue, out SyncAccessMode mode) ? mode : SyncAccessMode.ReadWrite);
    }

    public Task SetAccessModeAsync(SyncAccessMode mode)
    {
        Preferences.Set(SyncAccessModeKey, mode.ToString());
        return Task.CompletedTask;
    }

    public async Task<bool> ValidatePasswordAsync(string password)
    {
        var path = Preferences.Get(SyncPathKey, string.Empty);
        if (string.IsNullOrEmpty(path)) return false; 
        if (!await _syncFileService.ExistsAsync(path)) return false;

        try
        {
            var header = await ReadHeaderAsync(path);
            var salt = Convert.FromBase64String(header.Salt);
            var key = DeriveKey(password, salt, header.Iterations);
            var expectedVerifier = Convert.FromBase64String(header.Verifier);
            var actualVerifier = CreateVerifier(key);
            return CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier);
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> IsConfiguredAsync()
    {
        var path = Preferences.Get(SyncPathKey, string.Empty);
        if (string.IsNullOrEmpty(path)) return false;

        try
        {
            return await _syncFileService.ExistsAsync(path);
        }
        catch
        {
            // If checking existence fails (e.g. network error), assume not configured/offline
            // to prevent blocking local usage.
            return false;
        }
    }

    private async Task<byte[]> GetKeyAsync()
    {
        if (_cachedCommonKey != null) return _cachedCommonKey;

        var encryptedKeyStr = await SecureStorage.Default.GetAsync(SyncKeyStorageKey);
        if (string.IsNullOrEmpty(encryptedKeyStr)) throw new InvalidOperationException("Sync not configured.");

        if (!_appLockService.IsUnlocked) throw new InvalidOperationException("App locked.");

        var encryptedKey = Convert.FromBase64String(encryptedKeyStr);
        _cachedCommonKey = _appLockService.DecryptWithMasterKey(encryptedKey);
        return _cachedCommonKey;
    }

    private string GetPath()
    {
        var path = Preferences.Get(SyncPathKey, string.Empty);
        if (string.IsNullOrEmpty(path)) throw new InvalidOperationException("Sync path not configured.");
        return path;
    }

    public async Task SyncPasswordVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default)
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

    public async Task SyncDataVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default)
    {
        var path = GetPath();
        if (!await _syncFileService.ExistsAsync(path)) return; 

        var key = await GetKeyAsync();
        
        await _fileLock.WaitAsync(cancellationToken);
        try
        {
            var (header, content) = await ReadVaultFileAsync(path, key);
            
            var remoteEntries = content.DataVault.Select(d => d.ToModel()).ToList();
            var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);
            
            content.DataVault = result.MergedEntries
                .Select(PasswordVaultEntryDto.FromModel)
                .ToList();
            content.LastModified = DateTimeOffset.UtcNow;

            await WriteVaultFileAsync(path, header, content, key);
            
            localEntries.Clear();
            foreach(var e in result.MergedEntries) localEntries.Add(e);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public async Task SyncAuthenticatorAsync(IList<TotpEntry> localEntries, CancellationToken cancellationToken = default)
    {
         var path = GetPath();
        if (!await _syncFileService.ExistsAsync(path)) return;

        var key = await GetKeyAsync();
        
        await _fileLock.WaitAsync(cancellationToken);
        try
        {
            var (header, content) = await ReadVaultFileAsync(path, key);
            
            var remoteEntries = content.Authenticator.Select(d => d.ToModel()).ToList();
            var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);
            
            content.Authenticator = result.MergedEntries
                .Select(TotpEntryDto.FromModel)
                .ToList();
            content.LastModified = DateTimeOffset.UtcNow;

            await WriteVaultFileAsync(path, header, content, key);
            
             localEntries.Clear();
            foreach(var e in result.MergedEntries) localEntries.Add(e);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public async Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedPasswordVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default)
    {
         var path = GetPath();
        if (!await _syncFileService.ExistsAsync(path)) return new MergeResult<PasswordVaultEntry> { MergedEntries = localEntries.ToList() };

        var key = await GetKeyAsync();
        
        await _fileLock.WaitAsync(cancellationToken);
        try
        {
            var (header, content) = await ReadVaultFileAsync(path, key);
            
            var remoteEntries = content.PasswordVault.Select(d => d.ToModel()).ToList();
            var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);
            
            content.PasswordVault = result.MergedEntries
                .Select(PasswordVaultEntryDto.FromModel)
                .ToList();
            content.LastModified = DateTimeOffset.UtcNow;

            await WriteVaultFileAsync(path, header, content, key);
            
            return result;
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public async Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedDataVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default)
    {
         var path = GetPath();
        if (!await _syncFileService.ExistsAsync(path)) return new MergeResult<PasswordVaultEntry> { MergedEntries = localEntries.ToList() };

        var key = await GetKeyAsync();
        
        await _fileLock.WaitAsync(cancellationToken);
        try
        {
            var (header, content) = await ReadVaultFileAsync(path, key);
            
            var remoteEntries = content.DataVault.Select(d => d.ToModel()).ToList();
            var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);
            
            content.DataVault = result.MergedEntries
                .Select(PasswordVaultEntryDto.FromModel)
                .ToList();
            content.LastModified = DateTimeOffset.UtcNow;

            await WriteVaultFileAsync(path, header, content, key);
            
            return result;
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public async Task<Services.Vault.MergeResult<TotpEntry>> GetMergedAuthenticatorAsync(IList<TotpEntry> localEntries, CancellationToken cancellationToken = default)
    {
         var path = GetPath();
        if (!await _syncFileService.ExistsAsync(path)) return new MergeResult<TotpEntry> { MergedEntries = localEntries.ToList() };

        var key = await GetKeyAsync();
        
        await _fileLock.WaitAsync(cancellationToken);
        try
        {
            var (header, content) = await ReadVaultFileAsync(path, key);
            
            var remoteEntries = content.Authenticator.Select(d => d.ToModel()).ToList();
            var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);
            
            content.Authenticator = result.MergedEntries
                .Select(TotpEntryDto.FromModel)
                .ToList();
            content.LastModified = DateTimeOffset.UtcNow;

            await WriteVaultFileAsync(path, header, content, key);
            
            return result;
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public async Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedPasswordVaultReadOnlyAsync(
        IList<PasswordVaultEntry> localEntries,
        CancellationToken cancellationToken = default)
    {
        var path = GetPath();
        if (!await _syncFileService.ExistsAsync(path))
        {
            return new MergeResult<PasswordVaultEntry> { MergedEntries = localEntries.ToList() };
        }

        var key = await GetKeyAsync();

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

    public async Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedDataVaultReadOnlyAsync(
        IList<PasswordVaultEntry> localEntries,
        CancellationToken cancellationToken = default)
    {
        var path = GetPath();
        if (!await _syncFileService.ExistsAsync(path))
        {
            return new MergeResult<PasswordVaultEntry> { MergedEntries = localEntries.ToList() };
        }

        var key = await GetKeyAsync();

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

    public async Task<Services.Vault.MergeResult<TotpEntry>> GetMergedAuthenticatorReadOnlyAsync(
        IList<TotpEntry> localEntries,
        CancellationToken cancellationToken = default)
    {
        var path = GetPath();
        if (!await _syncFileService.ExistsAsync(path))
        {
            return new MergeResult<TotpEntry> { MergedEntries = localEntries.ToList() };
        }

        var key = await GetKeyAsync();

        await _fileLock.WaitAsync(cancellationToken);
        try
        {
            var (_, content) = await ReadVaultFileAsync(path, key);
            var remoteEntries = content.Authenticator.Select(d => d.ToModel()).ToList();
            return _vaultMergeService.MergeEntries(localEntries, remoteEntries);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    private const string MagicHeader = "PPP1"; // Password Phrase Producer v1

    private async Task<(ExternalVaultHeader Header, ExternalVaultContent Content)> ReadVaultFileAsync(string path, byte[] key)
    {
        string json;
        using (var stream = await _syncFileService.OpenReadAsync(path))
        {
            json = await ReadJsonFromStreamAsync(stream);
        }

        var file = JsonSerializer.Deserialize<ExternalVaultFile>(json, _jsonOptions);
        if (file == null) throw new InvalidDataException("Invalid sync file.");
        
        if (string.IsNullOrEmpty(file.CipherText)) throw new InvalidDataException("Sync file has no content (CipherText empty).");

        var encryptedBytes = Convert.FromBase64String(file.CipherText);
        if (encryptedBytes.Length < 28) throw new InvalidDataException("Sync file content invalid (too short).");

        var plainBytes = DecryptWithKey(encryptedBytes, key);
        var plainJson = Encoding.UTF8.GetString(plainBytes);
        
        var content = JsonSerializer.Deserialize<ExternalVaultContent>(plainJson, _jsonOptions) 
                      ?? new ExternalVaultContent();

        return (file.Header, content);
    }

    private async Task<ExternalVaultHeader> ReadHeaderAsync(string path)
    {
        string json;
        // Use Abstracted OpenRead
        using (var stream = await _syncFileService.OpenReadAsync(path))
        {
            json = await ReadJsonFromStreamAsync(stream);
        }
        var file = JsonSerializer.Deserialize<ExternalVaultFile>(json, _jsonOptions);
        return file?.Header ?? throw new InvalidDataException("Invalid sync file format.");
    }

    private async Task<string> ReadJsonFromStreamAsync(Stream stream)
    {
        // Try to read Magic Header (4 bytes)
        var magicBuffer = new byte[4];
        var read = await ReadExactlyAsync(stream, magicBuffer, 4);
        
        if (read < 4) 
        {
            if (read == 0) throw new InvalidDataException("Sync file is empty.");

            // Partial read at start: fallback to legacy?
            // If we read < 4 bytes and EOF, it can't be a valid magic header anyway.
            // Try to treat as legacy text provided it's not binary garbage.
            var sb = new StringBuilder(Encoding.UTF8.GetString(magicBuffer, 0, read));
            using var reader = new StreamReader(stream); 
            sb.Append(await reader.ReadToEndAsync());
            return sb.ToString();
        }

        var magic = Encoding.UTF8.GetString(magicBuffer);
        if (magic == MagicHeader)
        {
            // Read Length (4 bytes, Little Endian)
            var lenBuffer = new byte[4];
            if (await ReadExactlyAsync(stream, lenBuffer, 4) < 4) 
                throw new InvalidDataException("Corrupted sync file (missing length).");
            
            var length = BitConverter.ToInt32(lenBuffer, 0);
            
            if (length <= 0) throw new InvalidDataException($"Corrupted sync file (Invalid length: {length}).");

            // Read Content
            var contentBuffer = new byte[length];
            var totalRead = await ReadExactlyAsync(stream, contentBuffer, length);
            
            if (totalRead < length) 
                throw new InvalidDataException($"Unexpected end of stream. Expected {length}, got {totalRead}.");
            
            return Encoding.UTF8.GetString(contentBuffer);
        }
        else
        {
            // Legacy JSON format (no magic)
            if (stream.CanSeek)
            {
                stream.Seek(0, SeekOrigin.Begin);
                using var reader = new StreamReader(stream, leaveOpen: true);
                return await reader.ReadToEndAsync();
            }
            else
            {
                var part1 = Encoding.UTF8.GetString(magicBuffer);
                using var reader = new StreamReader(stream, leaveOpen: true);
                var part2 = await reader.ReadToEndAsync();
                return part1 + part2;
            }
        }
    }

    private async Task<int> ReadExactlyAsync(Stream stream, byte[] buffer, int count)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var read = await stream.ReadAsync(buffer, totalRead, count - totalRead);
            if (read == 0) break;
            totalRead += read;
        }
        return totalRead;
    }

    private async Task WriteVaultFileAsync(string path, ExternalVaultHeader header, ExternalVaultContent content, byte[] key)
    {
        var plainJson = JsonSerializer.Serialize(content, _jsonOptions);
        var plainBytes = Encoding.UTF8.GetBytes(plainJson);
        var encryptedBytes = EncryptWithKey(plainBytes, key);

        var file = new ExternalVaultFile
        {
            Header = header,
            CipherText = Convert.ToBase64String(encryptedBytes)
        };

        var json = JsonSerializer.Serialize(file, _jsonOptions);
        var jsonBytes = Encoding.UTF8.GetBytes(json);
        var length = jsonBytes.Length;
        var lengthBytes = BitConverter.GetBytes(length);
        var magicBytes = Encoding.UTF8.GetBytes(MagicHeader);

        using var stream = await _syncFileService.OpenWriteAsync(path);
        await stream.WriteAsync(magicBytes, 0, magicBytes.Length);
        await stream.WriteAsync(lengthBytes, 0, lengthBytes.Length);
        await stream.WriteAsync(jsonBytes, 0, jsonBytes.Length);
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
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, cipher, tag, plain);

        return plain;
    }
}
