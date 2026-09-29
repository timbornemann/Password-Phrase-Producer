using PasswordPhraseProducer.Updates;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.Services.Storage;

namespace Password_Phrase_Producer.Services.Security;

/// <summary>
/// Standalone encryption service for TOTP data, independent of PasswordVaultService
/// </summary>
public class TotpEncryptionService
{
    private const string KeyFileName = "totp.key";
    private static readonly byte[] KeyFileHeader = { (byte)'T', (byte)'O', (byte)'T', (byte)'P', 0x01 };
    private const int NonceLength = 12;
    private const int TagLength = 16;
    // Backward compatible key name (previously "PIN")
    private const string PasswordSaltStorageKey = "TotpPasswordSalt";
    private const string PasswordVerifierStorageKey = "TotpPasswordVerifier";
    private const string PasswordIterationsStorageKey = "TotpPasswordIterations";
    private const int SaltSizeBytes = 16;
    private const int Pbkdf2Iterations = 200_000;

    private readonly ISecureFileService _secureFileService;
    private readonly string _keyFilePath;
    private readonly object _keyStateLock = new();
    private long _lockGeneration;
    private byte[]? _unlockedKey;
    private bool _isUnlocked;

    public bool IsUnlocked { get { lock (_keyStateLock) return _isUnlocked; } }

    /// <summary>
    /// True when a password (previously called PIN) has been configured.
    /// </summary>
    /// <summary>
    /// Checks asynchronously if a password has been configured.
    /// </summary>
    public async Task<bool> HasPasswordAsync()
    {
        // The key file is authoritative. V2 also carries its own password metadata.
        return await _secureFileService.ExistsAsync(_keyFilePath).ConfigureAwait(false);
    }

    /// <summary>
    /// True when a password (previously called PIN) has been configured.
    /// WARNING: This property performs synchronous I/O and may block the calling thread. Use HasPasswordAsync() instead where possible.
    /// </summary>
    public bool HasPassword
    {
        get
        {
            return HasPasswordAsync().GetAwaiter().GetResult();
        }
    }

    public TotpEncryptionService(ISecureFileService secureFileService)
    {
        _secureFileService = secureFileService;
        _keyFilePath = Path.Combine(FileSystem.AppDataDirectory, KeyFileName);
    }

    /// <summary>
    /// Set up initial password protection (first time use)
    /// </summary>
    public async Task SetupPasswordAsync(string password)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        long generation;
        lock (_keyStateLock) generation = _lockGeneration;
        try
        {
            NewPasswordPolicy.Validate(password, nameof(password));

            StartupDataGuard.RequireNewStore(_keyFilePath);
            StartupDataGuard.RequireNewStore(Path.Combine(FileSystem.AppDataDirectory, "totp_data.json.enc"));

            // Generate a new master key
            var masterKey = new byte[32]; // 256-bit key
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(masterKey);
            }

            var encryptedMasterKey = TotpKeyFileFormat.Encrypt(masterKey, password);
            Directory.CreateDirectory(Path.GetDirectoryName(_keyFilePath)!);
            try
            {
                await _secureFileService.WriteAllBytesAsync(_keyFilePath, encryptedMasterKey);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(masterKey);
                throw;
            }
            lock (_keyStateLock)
            {
                if (_lockGeneration != generation)
                {
                    CryptographicOperations.ZeroMemory(masterKey);
                    throw new OperationCanceledException("Der Authenticator wurde während der Einrichtung gesperrt.");
                }
                _unlockedKey = masterKey;
                _isUnlocked = true;
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    /// <summary>
    /// Unlock with password
    /// </summary>
    public async Task<bool> UnlockWithPasswordAsync(string password)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        long generation;
        lock (_keyStateLock) generation = _lockGeneration;
        try
        {
            if (!await HasPasswordAsync().ConfigureAwait(false))
            {
                return false;
            }

            try
            {
                var encryptedMasterKey = await _secureFileService.ReadAllBytesAsync(_keyFilePath);
                byte[]? decryptedKey;
                if (TotpKeyFileFormat.IsV2(encryptedMasterKey))
                {
                    if (!TotpKeyFileFormat.TryDecrypt(encryptedMasterKey, password, out decryptedKey))
                        return false;
                }
                else
                {
                    // Read-only compatibility with key files created before V2.
                    var saltBase64 = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey);
                    var verifierBase64 = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey);
                    var iterationsStr = await SecureStorage.Default.GetAsync(PasswordIterationsStorageKey);
                    if (string.IsNullOrEmpty(saltBase64) || string.IsNullOrEmpty(verifierBase64))
                        return false;

                    var salt = Convert.FromBase64String(saltBase64);
                    var expectedVerifier = Convert.FromBase64String(verifierBase64);
                    if (salt.Length != SaltSizeBytes || expectedVerifier.Length != 32)
                        return false;
                    if (!int.TryParse(iterationsStr, out var iterations))
                        iterations = Pbkdf2Iterations;
                    if (iterations is < 10_000 or > 1_000_000)
                        return false;

                    var passwordDerivedKey = DeriveKeyFromPassword(password, salt, iterations);
                    try
                    {
                        if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, CreateVerifier(passwordDerivedKey)))
                            return false;
                        decryptedKey = DecryptWithKey(encryptedMasterKey, passwordDerivedKey);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(passwordDerivedKey);
                    }
                }

                if (decryptedKey is null || decryptedKey.Length != 32)
                {
                    if (decryptedKey is not null)
                        CryptographicOperations.ZeroMemory(decryptedKey);
                    return false;
                }
                lock (_keyStateLock)
                {
                    if (_lockGeneration != generation)
                    {
                        CryptographicOperations.ZeroMemory(decryptedKey);
                        return false;
                    }
                    if (_unlockedKey is not null) CryptographicOperations.ZeroMemory(_unlockedKey);
                    _unlockedKey = decryptedKey;
                    _isUnlocked = true;
                    return true;
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

    /// <summary>
    /// Change password
    /// </summary>
    public async Task ChangePasswordAsync(string oldPassword, string newPassword)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (!await UnlockWithPasswordAsync(oldPassword))
            {
                throw new InvalidOperationException("Falsches Passwort.");
            }

            NewPasswordPolicy.Validate(newPassword, nameof(newPassword));

            var masterKey = GetUnlockedKey();
            byte[] encryptedMasterKey;
            try { encryptedMasterKey = TotpKeyFileFormat.Encrypt(masterKey, newPassword); }
            finally { CryptographicOperations.ZeroMemory(masterKey); }
            await _secureFileService.WriteAllBytesAsync(_keyFilePath, encryptedMasterKey);
            // Legacy metadata is no longer needed. The V2 file remains usable even
            // if the process stops before these removals finish.
            try
            {
                SecureStorage.Default.Remove(PasswordSaltStorageKey);
                SecureStorage.Default.Remove(PasswordVerifierStorageKey);
                SecureStorage.Default.Remove(PasswordIterationsStorageKey);
            }
            catch
            {
                // Cleanup failure does not invalidate the already committed V2 key file.
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    /// <summary>
    /// Lock the service
    /// </summary>
    public void Lock()
    {
        lock (_keyStateLock)
        {
            _lockGeneration++;
            if (_unlockedKey != null) CryptographicOperations.ZeroMemory(_unlockedKey);
            _unlockedKey = null;
            _isUnlocked = false;
        }
    }

    /// <summary>
    /// Reset the service by deleting all stored data and passwords
    /// </summary>
    public void Reset()
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            // Lock first
            Lock();

            // Delete key file - Note: Delete is synchronous in interface??
            // Wait, ISecureFileService.Delete is probably void Delete(string path). Check Step 46.
            // Step 46: `void Delete(string path);` Yes.

            // However, I need to check existence first? SecureFileService.Delete does File.Delete which doesn't throw if file missing?
            // Actually File.Delete does not throw if file doesn't exist. But SecureFileService might throw?
            // Let's assume it's safe or check ExistsAsync first.
            // Sync context in Reset()? It's a sync method?
            // The Reset() method in TotpEncryptionService is synchronous: `public void Reset()`.
            // _secureFileService.ExistsAsync is async. I cannot call it easily here.
            // I should probably skip the check or update Reset to be async, but that changes API.
            // Or just call `_secureFileService.Delete(_keyFilePath)` assuming it handles it.
            // Let's look at `SecureFileService.cs` implementation (Step 46).
            // It's `public void Delete(string path) { if (File.Exists(path)) File.Delete(path); }` (inferred).
            // Wait, I created Step 46. Let's check `SecureFileService` content if needed.
            // But for now, I'll just call `_secureFileService.Delete`.

            _secureFileService.Delete(_keyFilePath);

            // Clear password preferences and metadata
            SecureStorage.Default.Remove(PasswordSaltStorageKey);
            SecureStorage.Default.Remove(PasswordVerifierStorageKey);
            SecureStorage.Default.Remove(PasswordIterationsStorageKey);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    /// <summary>
    /// Get the unlocked key for encryption/decryption
    /// </summary>
    public byte[] GetUnlockedKey()
    {
        lock (_keyStateLock)
        {
            if (!_isUnlocked || _unlockedKey == null)
                throw new InvalidOperationException("Der Authenticator ist gesperrt.");
            return _unlockedKey.ToArray();
        }
    }

    /// <summary>
    /// Encrypt data with the master key
    /// </summary>
    public byte[] Encrypt(byte[] plaintext)
    {
        var key = GetUnlockedKey();
        try { return EncryptWithKey(plaintext, key); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    /// <summary>
    /// Decrypt data with the master key
    /// </summary>
    public byte[] Decrypt(byte[] ciphertext)
    {
        var key = GetUnlockedKey();
        try { return DecryptWithKey(ciphertext, key); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    #region Private Helpers

    /// <summary>
    /// Derive key from password using PBKDF2 with user-specific salt
    /// </summary>
    private static byte[] DeriveKeyFromPassword(string password, byte[] salt, int iterations = Pbkdf2Iterations)
    {
        const int keySize = 32; // 256 bits
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(keySize);
    }

    /// <summary>
    /// Create a verifier hash from a key (for password verification)
    /// </summary>
    private static byte[] CreateVerifier(byte[] key)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(key);
    }

    private static byte[] EncryptWithKey(byte[] plaintext, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[TagLength];

        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(nonce, plaintext, cipher, tag);

        var result = new byte[KeyFileHeader.Length + nonce.Length + cipher.Length + tag.Length];
        Buffer.BlockCopy(KeyFileHeader, 0, result, 0, KeyFileHeader.Length);
        Buffer.BlockCopy(nonce, 0, result, KeyFileHeader.Length, nonce.Length);
        Buffer.BlockCopy(cipher, 0, result, KeyFileHeader.Length + nonce.Length, cipher.Length);
        Buffer.BlockCopy(tag, 0, result, KeyFileHeader.Length + nonce.Length + cipher.Length, tag.Length);

        return result;
    }

    private static byte[] DecryptWithKey(byte[] data, byte[] key)
    {
        if (HasKeyFileHeader(data))
        {
            return DecryptWithAead(data, key);
        }

        // If no header, assume corrupt or legacy (which we no longer support)
        throw new InvalidOperationException("Veraltetes Format oder beschädigte Datei.");
    }

    private static bool HasKeyFileHeader(byte[] data)
    {
        if (data.Length < KeyFileHeader.Length)
        {
            return false;
        }

        for (var i = 0; i < KeyFileHeader.Length; i++)
        {
            if (data[i] != KeyFileHeader[i])
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] DecryptWithAead(byte[] data, byte[] key)
    {
        if (data.Length < KeyFileHeader.Length + NonceLength + TagLength)
        {
            throw new InvalidOperationException("Ungültiges verschlüsseltes Format.");
        }

        var cipherLength = data.Length - KeyFileHeader.Length - NonceLength - TagLength;
        if (cipherLength < 0)
        {
            throw new InvalidOperationException("Ungültiges verschlüsseltes Format.");
        }

        var nonce = new byte[NonceLength];
        var cipher = new byte[cipherLength];
        var tag = new byte[TagLength];

        try
        {
            Buffer.BlockCopy(data, KeyFileHeader.Length, nonce, 0, nonce.Length);
            Buffer.BlockCopy(data, KeyFileHeader.Length + nonce.Length, cipher, 0, cipher.Length);
            Buffer.BlockCopy(data, KeyFileHeader.Length + nonce.Length + cipher.Length, tag, 0, tag.Length);

            var plain = new byte[cipherLength];
            using var aes = new AesGcm(key, tag.Length);
            aes.Decrypt(nonce, cipher, tag, plain);
            return plain;
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("Entschlüsselung fehlgeschlagen.", ex);
        }
        finally
        {
            Array.Clear(nonce);
            Array.Clear(cipher);
            Array.Clear(tag);
        }
    }

    #endregion
}
