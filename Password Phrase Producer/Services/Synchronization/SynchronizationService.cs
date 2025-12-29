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
using static Password_Phrase_Producer.Models.SyncModels;

namespace Password_Phrase_Producer.Services.Synchronization;

public interface ISynchronizationService
{
    Task<bool> IsConfiguredAsync();
    Task ConfigureAsync(string path, string password);
    Task<bool> ValidatePasswordAsync(string password); // Checks if password matches existing file
    Task SyncPasswordVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default);
    Task SyncDataVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default);
    Task SyncAuthenticatorAsync(IList<TotpEntry> localEntries, CancellationToken cancellationToken = default);
    Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedPasswordVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default);
    Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedDataVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default);
    Task<Services.Vault.MergeResult<TotpEntry>> GetMergedAuthenticatorAsync(IList<TotpEntry> localEntries, CancellationToken cancellationToken = default);
}

public class SynchronizationService : ISynchronizationService
{
    private const string SyncPathKey = "SyncFilePath";
    private const string SyncKeyStorageKey = "SyncCommonKey_Encrypted";
    private const int KeySize = 32;
    private const int SaltSize = 16;
    private const int Iterations = 200_000;

    private readonly IAppLockService _appLockService;
    private readonly VaultMergeService _vaultMergeService;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false };

    private byte[]? _cachedCommonKey;

    public async Task<bool> IsConfiguredAsync() => Preferences.ContainsKey(SyncPathKey) && await SecureStorage.Default.GetAsync(SyncKeyStorageKey).ConfigureAwait(false) != null;

    public SynchronizationService(IAppLockService appLockService, VaultMergeService vaultMergeService)
    {
        _appLockService = appLockService;
        _vaultMergeService = vaultMergeService;
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

        // If file exists, try to validate instead of overwrite? 
        // User flow usually explicitly sets up sync. If file exists, we should probably check if password matches.
        if (File.Exists(path) && new FileInfo(path).Length > 0)
        {
            try 
            {
                var existingHeader = await ReadHeaderAsync(path);
                if (existingHeader != null)
                {
                    // Validate
                    var existingSalt = Convert.FromBase64String(existingHeader.Salt);
                    var existingKey = await Task.Run(() => DeriveKey(password, existingSalt, existingHeader.Iterations)).ConfigureAwait(false);
                    var expectedVerifier = Convert.FromBase64String(existingHeader.Verifier);
                    var actualVerifier = CreateVerifier(existingKey);
                    
                    if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
                    {
                         throw new InvalidOperationException("Das angegebene Passwort stimmt nicht mit der existierenden Sync-Datei überein.");
                    }
                    
                    key = existingKey; // Use the one derived from file's salt
                    header = existingHeader; // Keep existing header
                }
            }
            catch (Exception ex) when (ex is not InvalidOperationException)
            {
                // File might be corrupt or not a vault file, overwrite?
                // For safety, let's backup? No, just throw for now.
                throw new InvalidOperationException("Die Datei existiert bereits, ist aber keine gültige oder lesbare Sync-Datei.", ex);
            }
        }
        else
        {
            // Create new empty file
            var content = new ExternalVaultContent();
            await WriteVaultFileAsync(path, header, content, key);
        }

        // Store configuration
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

    public async Task<bool> ValidatePasswordAsync(string password)
    {
        var path = Preferences.Get(SyncPathKey, string.Empty);
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;

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
        var result = await GetMergedPasswordVaultAsync(localEntries, cancellationToken);
        // "GetMerged" already does the read-merge logic. Now we update local entries list in place if needed?
        // Actually, the caller passed the list. Use VaultMergeService result.
        
        // Update local list
        localEntries.Clear();
        foreach (var entry in result.MergedEntries)
        {
            localEntries.Add(entry);
        }
        
        // Write happens inside GetMerged... -> Wait, GetMerged should probably just return the result.
        // Actually, for "Sync", we want to SAVE the result to the file as well.
        // Let's refactor: GetMerged loads, merges. Caller updates local. But saving to external file?
        
        // Re-design:
        // 1. Read External
        // 2. Merge with Local
        // 3. Update External (Write)
        // 4. Return Merged List to Local Service to save locally.
        
        // Implementation below does this.
    }

    public async Task SyncDataVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default)
    {
        // Similar to PasswordVault but targeting DataVault section
        var path = GetPath();
        if (!File.Exists(path)) return; // Should configure first

        var key = await GetKeyAsync();
        
        await _fileLock.WaitAsync(cancellationToken);
        try
        {
            var (header, content) = await ReadVaultFileAsync(path, key);
            
            var remoteEntries = content.DataVault.Select(d => d.ToModel()).ToList();
            var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);
            
            // Update content
            content.DataVault = result.MergedEntries
                .Select(PasswordVaultEntryDto.FromModel)
                .ToList();
            content.LastModified = DateTimeOffset.UtcNow;

            await WriteVaultFileAsync(path, header, content, key);
            
            // Update local ref
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
        if (!File.Exists(path)) return;

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

    // Combined implementations to avoid code duplication
    public async Task<Services.Vault.MergeResult<PasswordVaultEntry>> GetMergedPasswordVaultAsync(IList<PasswordVaultEntry> localEntries, CancellationToken cancellationToken = default)
    {
         var path = GetPath();
        if (!File.Exists(path)) return new MergeResult<PasswordVaultEntry> { MergedEntries = localEntries.ToList() };

        var key = await GetKeyAsync();
        
        await _fileLock.WaitAsync(cancellationToken);
        try
        {
            var (header, content) = await ReadVaultFileAsync(path, key);
            
            var remoteEntries = content.PasswordVault.Select(d => d.ToModel()).ToList();
            var result = _vaultMergeService.MergeEntries(localEntries, remoteEntries);
            
            // Write back merged result to external file to ensure it's up to date
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
        // Implementing logic here for consistency
         var path = GetPath();
        if (!File.Exists(path)) return new MergeResult<PasswordVaultEntry> { MergedEntries = localEntries.ToList() };

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
        if (!File.Exists(path)) return new MergeResult<TotpEntry> { MergedEntries = localEntries.ToList() };

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

    // Helper methods

    private async Task<ExternalVaultHeader> ReadHeaderAsync(string path)
    {
        using var stream = File.OpenRead(path);
        using var reader = new StreamReader(stream);
        var json = await reader.ReadToEndAsync();
        var file = JsonSerializer.Deserialize<ExternalVaultFile>(json, _jsonOptions);
        return file?.Header ?? throw new InvalidDataException("Invalid sync file format.");
    }

    private async Task<(ExternalVaultHeader Header, ExternalVaultContent Content)> ReadVaultFileAsync(string path, byte[] key)
    {
        string json;
        using (var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        using (var reader = new StreamReader(stream))
        {
            json = await reader.ReadToEndAsync();
        }
        
        var file = JsonSerializer.Deserialize<ExternalVaultFile>(json, _jsonOptions);
        if (file == null) throw new InvalidDataException("Invalid sync file.");

        var encryptedBytes = Convert.FromBase64String(file.CipherText);
        var plainBytes = DecryptWithKey(encryptedBytes, key);
        var plainJson = Encoding.UTF8.GetString(plainBytes);
        
        var content = JsonSerializer.Deserialize<ExternalVaultContent>(plainJson, _jsonOptions) 
                      ?? new ExternalVaultContent();

        return (file.Header, content);
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
        
        // Write atomically if possible, but for simple file sharing we just overwrite
        using var stream = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
        using var writer = new StreamWriter(stream);
        await writer.WriteAsync(json);
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
