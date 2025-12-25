using System.Security.Cryptography;
using System.Text;

namespace Password_Phrase_Producer.Services.Security;

/// <summary>
/// Standalone encryption service for TOTP data, independent of PasswordVaultService
/// </summary>
public class TotpEncryptionService
{
    private const string KeyFileName = "totp.key";
    // Backward compatible key name (previously "PIN")
    private const string PasswordPrefsKey = "totp_pin_hash";
    private readonly string _keyFilePath;
    private byte[]? _unlockedKey;
    private bool _isUnlocked;

    public bool IsUnlocked => _isUnlocked;

    /// <summary>
    /// True when a password (previously called PIN) has been configured.
    /// </summary>
    public bool HasPassword => Preferences.ContainsKey(PasswordPrefsKey);

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

        // Encrypt the master key with password-derived key
        var passwordDerivedKey = DeriveKeyFromPassword(password);
        var encryptedMasterKey = EncryptWithKey(masterKey, passwordDerivedKey);

        // Save encrypted master key to file
        Directory.CreateDirectory(Path.GetDirectoryName(_keyFilePath)!);
        await File.WriteAllBytesAsync(_keyFilePath, encryptedMasterKey);

        // Store password hash for verification
        var passwordHash = HashPassword(password);
        Preferences.Set(PasswordPrefsKey, passwordHash);

        // Unlock immediately
        _unlockedKey = masterKey;
        _isUnlocked = true;
    }

    /// <summary>
    /// Unlock with password
    /// </summary>
    public async Task<bool> UnlockWithPasswordAsync(string password)
    {
        if (!HasPassword)
        {
            return false;
        }

        // Verify password hash
        var storedHash = Preferences.Get(PasswordPrefsKey, string.Empty);
        var passwordHash = HashPassword(password);

        if (storedHash != passwordHash)
        {
            return false; // Wrong password
        }

        // Load and decrypt master key
        if (!File.Exists(_keyFilePath))
        {
            return false;
        }

        var encryptedMasterKey = await File.ReadAllBytesAsync(_keyFilePath);
        var passwordDerivedKey = DeriveKeyFromPassword(password);

        try
        {
            _unlockedKey = DecryptWithKey(encryptedMasterKey, passwordDerivedKey);
            _isUnlocked = true;
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

        // Re-encrypt master key with new password
        var newPasswordDerivedKey = DeriveKeyFromPassword(newPassword);
        try
        {
            var encryptedMasterKey = EncryptWithKey(_unlockedKey, newPasswordDerivedKey);

            await File.WriteAllBytesAsync(_keyFilePath, encryptedMasterKey);

            // Update password hash
            var newPasswordHash = HashPassword(newPassword);
            Preferences.Set(PasswordPrefsKey, newPasswordHash);
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
        return DecryptWithKey(ciphertext, key);
    }

    #region Private Helpers

    private static byte[] DeriveKeyFromPassword(string password)
    {
        // Use PBKDF2 to derive a key from password
        const int iterations = 100000;
        const int keySize = 32; // 256 bits

        // Use a fixed salt (in production, should be random per setup, but for simplicity)
        var salt = Encoding.UTF8.GetBytes("TotpAuthenticatorSalt_v1");

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(keySize);
    }

    private static string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }

    private static byte[] EncryptWithKey(byte[] plaintext, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        var ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);

        // Prepend IV to ciphertext
        var result = new byte[aes.IV.Length + ciphertext.Length];
        Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
        Buffer.BlockCopy(ciphertext, 0, result, aes.IV.Length, ciphertext.Length);

        return result;
    }

    private static byte[] DecryptWithKey(byte[] ciphertextWithIv, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;

        // Extract IV (first 16 bytes)
        var iv = new byte[aes.IV.Length];
        Buffer.BlockCopy(ciphertextWithIv, 0, iv, 0, iv.Length);
        aes.IV = iv;

        // Extract ciphertext (rest)
        var ciphertext = new byte[ciphertextWithIv.Length - iv.Length];
        Buffer.BlockCopy(ciphertextWithIv, iv.Length, ciphertext, 0, ciphertext.Length);

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }

    #endregion
}

