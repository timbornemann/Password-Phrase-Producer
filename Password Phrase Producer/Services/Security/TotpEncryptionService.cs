using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Maui.Storage;

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
    private const string PasswordPrefsKey = "totp_pin_hash";
    private const string PasswordSaltStorageKey = "TotpPasswordSalt";
    private const string PasswordVerifierStorageKey = "TotpPasswordVerifier";
    private const string PasswordIterationsStorageKey = "TotpPasswordIterations";
    private const int SaltSizeBytes = 16;
    private const int Pbkdf2Iterations = 200_000;
    private readonly string _keyFilePath;
    private byte[]? _unlockedKey;
    private bool _isUnlocked;

    public bool IsUnlocked => _isUnlocked;

    /// <summary>
    /// True when a password (previously called PIN) has been configured.
    /// </summary>
    /// <summary>
    /// Checks asynchronously if a password has been configured.
    /// </summary>
    public async Task<bool> HasPasswordAsync()
    {
        // Check new format first (SecureStorage)
        var salt = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(salt))
        {
            return true;
        }
        // Fallback to old format (Preferences)
        return Preferences.ContainsKey(PasswordPrefsKey);
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

    // Backward compatible alias for older callers
    public bool HasPin => HasPassword;

    public TotpEncryptionService()
    {
        _keyFilePath = Path.Combine(FileSystem.AppDataDirectory, KeyFileName);
    }

    /// <summary>
    /// Set up initial password protection (first time use)
    /// </summary>
    public async Task SetupPasswordAsync(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Passwort darf nicht leer sein.", nameof(password));
        }

        // Generate a new master key
        var masterKey = new byte[32]; // 256-bit key
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(masterKey);
        }

        // Generate a unique salt for this user
        var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        var passwordDerivedKey = DeriveKeyFromPassword(password, salt);
        try
        {
            var encryptedMasterKey = EncryptWithKey(masterKey, passwordDerivedKey);
            var verifier = CreateVerifier(passwordDerivedKey);

            // Save encrypted master key to file
            Directory.CreateDirectory(Path.GetDirectoryName(_keyFilePath)!);
            await File.WriteAllBytesAsync(_keyFilePath, encryptedMasterKey);

            // Store password metadata (salt, verifier, iterations) in SecureStorage
            await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, Convert.ToBase64String(salt));
            await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, Convert.ToBase64String(verifier));
            await SecureStorage.Default.SetAsync(PasswordIterationsStorageKey, Pbkdf2Iterations.ToString());

            // Unlock immediately
            _unlockedKey = masterKey;
            _isUnlocked = true;
        }
        finally
        {
            Array.Clear(passwordDerivedKey);
        }
    }

    /// <summary>
    /// Unlock with password
    /// </summary>
    public async Task<bool> UnlockWithPasswordAsync(string password)
    {
        if (!await HasPasswordAsync().ConfigureAwait(false))
        {
            return false;
        }

        // Get password metadata
        var saltBase64 = await SecureStorage.Default.GetAsync(PasswordSaltStorageKey);
        var verifierBase64 = await SecureStorage.Default.GetAsync(PasswordVerifierStorageKey);
        var iterationsStr = await SecureStorage.Default.GetAsync(PasswordIterationsStorageKey);

        // Fallback to old format if metadata not found (backward compatibility)
        if (string.IsNullOrEmpty(saltBase64) || string.IsNullOrEmpty(verifierBase64))
        {
            return await UnlockWithPasswordLegacyAsync(password);
        }

        if (!int.TryParse(iterationsStr, out var iterations) || iterations <= 0)
        {
            iterations = Pbkdf2Iterations;
        }

        var salt = Convert.FromBase64String(saltBase64);
        var passwordDerivedKey = DeriveKeyFromPassword(password, salt, iterations);

        try
        {
            // Verify password using verifier
            var expectedVerifier = Convert.FromBase64String(verifierBase64);
            var actualVerifier = CreateVerifier(passwordDerivedKey);

            if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
            {
                return false; // Wrong password
            }

            // Load and decrypt master key
            if (!File.Exists(_keyFilePath))
            {
                return false;
            }

            var encryptedMasterKey = await File.ReadAllBytesAsync(_keyFilePath);
            _unlockedKey = DecryptWithKey(encryptedMasterKey, passwordDerivedKey, out var usedLegacyFormat);
            _isUnlocked = true;

            if (usedLegacyFormat)
            {
                await MigrateKeyFileAsync(_unlockedKey, passwordDerivedKey).ConfigureAwait(false);
            }
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            // Passwort-abgeleiteter Schlüssel aus dem Speicher löschen
            Array.Clear(passwordDerivedKey);
        }
    }

    /// <summary>
    /// Legacy unlock method for backward compatibility with old format
    /// </summary>
    private async Task<bool> UnlockWithPasswordLegacyAsync(string password)
    {
        // Verify password hash (old format)
        var storedHash = Preferences.Get(PasswordPrefsKey, string.Empty);
        if (string.IsNullOrEmpty(storedHash))
        {
            return false;
        }

        var passwordHash = HashPasswordLegacy(password);
        if (storedHash != passwordHash)
        {
            return false; // Wrong password
        }

        // Load and decrypt master key with legacy fixed salt
        if (!File.Exists(_keyFilePath))
        {
            return false;
        }

        var encryptedMasterKey = await File.ReadAllBytesAsync(_keyFilePath);
        var passwordDerivedKey = DeriveKeyFromPasswordLegacy(password);

        try
        {
            _unlockedKey = DecryptWithKey(encryptedMasterKey, passwordDerivedKey, out var usedLegacyFormat);
            _isUnlocked = true;

            if (usedLegacyFormat)
            {
                await MigrateKeyFileAsync(_unlockedKey, passwordDerivedKey).ConfigureAwait(false);
            }
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            Array.Clear(passwordDerivedKey);
        }
    }

    /// <summary>
    /// Change password
    /// </summary>
    public async Task ChangePasswordAsync(string oldPassword, string newPassword)
    {
        if (!await UnlockWithPasswordAsync(oldPassword))
        {
            throw new InvalidOperationException("Falsches Passwort.");
        }

        if (_unlockedKey == null)
        {
            throw new InvalidOperationException("Kein Schlüssel vorhanden.");
        }

        if (string.IsNullOrWhiteSpace(newPassword))
        {
            throw new ArgumentException("Passwort darf nicht leer sein.", nameof(newPassword));
        }

        // Generate new salt for the new password
        var newSalt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        var newPasswordDerivedKey = DeriveKeyFromPassword(newPassword, newSalt);
        try
        {
            var encryptedMasterKey = EncryptWithKey(_unlockedKey, newPasswordDerivedKey);
            var newVerifier = CreateVerifier(newPasswordDerivedKey);

            await File.WriteAllBytesAsync(_keyFilePath, encryptedMasterKey);

            // Update password metadata
            await SecureStorage.Default.SetAsync(PasswordSaltStorageKey, Convert.ToBase64String(newSalt));
            await SecureStorage.Default.SetAsync(PasswordVerifierStorageKey, Convert.ToBase64String(newVerifier));
            await SecureStorage.Default.SetAsync(PasswordIterationsStorageKey, Pbkdf2Iterations.ToString());

            // Remove old password hash if it exists
            Preferences.Remove(PasswordPrefsKey);
        }
        finally
        {
            // Neuer Passwort-abgeleiteter Schlüssel aus dem Speicher löschen
            Array.Clear(newPasswordDerivedKey);
        }
    }

    // Backward compatible wrappers
    public Task SetupPinAsync(string pin) => SetupPasswordAsync(pin);
    public Task<bool> UnlockWithPinAsync(string pin) => UnlockWithPasswordAsync(pin);
    public Task ChangePinAsync(string oldPin, string newPin) => ChangePasswordAsync(oldPin, newPin);

    /// <summary>
    /// Lock the service
    /// </summary>
    public void Lock()
    {
        if (_unlockedKey != null)
        {
            Array.Clear(_unlockedKey, 0, _unlockedKey.Length);
            _unlockedKey = null;
        }
        _isUnlocked = false;
    }

    /// <summary>
    /// Reset the service by deleting all stored data and passwords
    /// </summary>
    public void Reset()
    {
        // Lock first
        Lock();

        // Delete key file
        if (File.Exists(_keyFilePath))
        {
            File.Delete(_keyFilePath);
        }

        // Clear password preferences and metadata
        Preferences.Remove(PasswordPrefsKey);
        SecureStorage.Default.Remove(PasswordSaltStorageKey);
        SecureStorage.Default.Remove(PasswordVerifierStorageKey);
        SecureStorage.Default.Remove(PasswordIterationsStorageKey);
    }

    /// <summary>
    /// Get the unlocked key for encryption/decryption
    /// </summary>
    public byte[] GetUnlockedKey()
    {
        if (!_isUnlocked || _unlockedKey == null)
        {
            throw new InvalidOperationException("Der Authenticator ist gesperrt.");
        }
        return _unlockedKey;
    }

    /// <summary>
    /// Encrypt data with the master key
    /// </summary>
    public byte[] Encrypt(byte[] plaintext)
    {
        var key = GetUnlockedKey();
        return EncryptWithKey(plaintext, key);
    }

    /// <summary>
    /// Decrypt data with the master key
    /// </summary>
    public byte[] Decrypt(byte[] ciphertext)
    {
        var key = GetUnlockedKey();
        return DecryptWithKey(ciphertext, key, out _);
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
    /// Legacy key derivation with fixed salt (for backward compatibility)
    /// </summary>
    private static byte[] DeriveKeyFromPasswordLegacy(string password)
    {
        const int iterations = 100000;
        const int keySize = 32;
        var salt = Encoding.UTF8.GetBytes("TotpAuthenticatorSalt_v1");
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

    /// <summary>
    /// Legacy password hashing (for backward compatibility only)
    /// </summary>
    private static string HashPasswordLegacy(string password)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
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

    private static byte[] DecryptWithKey(byte[] data, byte[] key, out bool usedLegacyFormat)
    {
        if (HasKeyFileHeader(data))
        {
            usedLegacyFormat = false;
            return DecryptWithAead(data, key);
        }

        usedLegacyFormat = true;
        return DecryptWithLegacyFormat(data, key);
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

    private static byte[] DecryptWithLegacyFormat(byte[] data, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;

        var ivLength = aes.IV.Length;
        if (data.Length < ivLength)
        {
            throw new InvalidOperationException("Ungültiges verschlüsseltes Format.");
        }

        var iv = new byte[ivLength];
        var ciphertext = new byte[data.Length - ivLength];

        try
        {
            Buffer.BlockCopy(data, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(data, iv.Length, ciphertext, 0, ciphertext.Length);
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }
        finally
        {
            Array.Clear(iv);
            Array.Clear(ciphertext);
        }
    }

    private async Task MigrateKeyFileAsync(byte[] masterKey, byte[] passwordDerivedKey)
    {
        var encryptedMasterKey = EncryptWithKey(masterKey, passwordDerivedKey);
        Directory.CreateDirectory(Path.GetDirectoryName(_keyFilePath)!);
        await File.WriteAllBytesAsync(_keyFilePath, encryptedMasterKey).ConfigureAwait(false);
    }

    #endregion
}
