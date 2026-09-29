using PasswordPhraseProducer.Updates;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.Services.Storage;

namespace Password_Phrase_Producer.Services.Security;

/// <summary>
/// Standalone encryption service for TOTP data, independent of PasswordVaultService
/// </summary>
public class TotpEncryptionService
{
    private const string KeyFileName = "totp.key";
    private const string DataFileName = "totp_data.json.enc";
    private const string BiometricKeyStorageKey = "TotpBiometricKey_V1";
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
    private readonly IBiometricAuthenticationService _biometricService;
    private readonly string _keyFilePath;
    private readonly string _dataFilePath;
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

    public TotpEncryptionService(ISecureFileService secureFileService, IBiometricAuthenticationService biometricService)
    {
        _secureFileService = secureFileService;
        _biometricService = biometricService;
        _keyFilePath = Path.Combine(FileSystem.AppDataDirectory, KeyFileName);
        _dataFilePath = Path.Combine(FileSystem.AppDataDirectory, DataFileName);
    }

    public async Task<bool> HasBiometricKeyAsync()
    {
        if (!await HasPasswordAsync().ConfigureAwait(false)) return false;
        var stored = await SecureStorage.Default.GetAsync(BiometricKeyStorageKey).ConfigureAwait(false);
        if (!TotpBiometricKeyRecord.TryParse(stored, out var record) || record is null) return false;
        var keyFile = await _secureFileService.ReadAllBytesAsync(_keyFilePath).ConfigureAwait(false);
        return record.MatchesKeyFile(keyFile);
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
            StartupDataGuard.RequireNewStore(_dataFilePath);

            // A new store must never inherit biometric access from a deleted one.
            SecureStorage.Default.Remove(BiometricKeyStorageKey);

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
                try
                {
                    await VerifyDataFileAsync(decryptedKey).ConfigureAwait(false);
                }
                catch
                {
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

    public async Task<bool> UnlockWithBiometricsAsync(CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        long generation;
        lock (_keyStateLock) generation = _lockGeneration;
        try
        {
            if (!await HasPasswordAsync().ConfigureAwait(false)) return false;
            var stored = await SecureStorage.Default.GetAsync(BiometricKeyStorageKey).ConfigureAwait(false);
            if (!TotpBiometricKeyRecord.TryParse(stored, out var record) || record is null) return false;

            var keyFile = await _secureFileService.ReadAllBytesAsync(_keyFilePath, cancellationToken).ConfigureAwait(false);
            if (!record.MatchesKeyFile(keyFile)) return false;

            byte[]? key = null;
            try
            {
                key = await _biometricService.DecryptAsync(Convert.FromBase64String(record.EncryptedKey), cancellationToken)
                    .ConfigureAwait(false);
                if (!record.MatchesMasterKey(key)) return false;
                await VerifyDataFileAsync(key, cancellationToken).ConfigureAwait(false);

                lock (_keyStateLock)
                {
                    if (_lockGeneration != generation) return false;
                    if (_unlockedKey is not null) CryptographicOperations.ZeroMemory(_unlockedKey);
                    _unlockedKey = key;
                    key = null;
                    _isUnlocked = true;
                    return true;
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or CryptographicException or
                                       InvalidOperationException or InvalidDataException or FormatException)
            {
                return false;
            }
            finally
            {
                if (key is not null) CryptographicOperations.ZeroMemory(key);
            }
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
        try
        {
            if (!enabled)
            {
                SecureStorage.Default.Remove(BiometricKeyStorageKey);
                return;
            }

            if (!await _biometricService.IsAvailableAsync(cancellationToken).ConfigureAwait(false))
                throw new InvalidOperationException("Biometrische Anmeldung ist auf diesem Gerät nicht verfügbar.");

            byte[] key;
            long generation;
            lock (_keyStateLock)
            {
                if (!_isUnlocked || _unlockedKey is null)
                    throw new InvalidOperationException("Der Authenticator ist gesperrt.");
                generation = _lockGeneration;
                key = _unlockedKey.ToArray();
            }

            try
            {
                var keyFile = await _secureFileService.ReadAllBytesAsync(_keyFilePath, cancellationToken).ConfigureAwait(false);
                if (keyFile.Length == 0)
                    throw new InvalidDataException("Der Authenticator-Schlüssel fehlt.");
                var encrypted = await _biometricService.EncryptAsync(key, cancellationToken).ConfigureAwait(false);
                var record = TotpBiometricKeyRecord.Create(encrypted, keyFile, key);
                EnsureStillUnlocked(key, generation);
                await SecureStorage.Default.SetAsync(BiometricKeyStorageKey, record.Serialize()).ConfigureAwait(false);
                try { EnsureStillUnlocked(key, generation); }
                catch
                {
                    SecureStorage.Default.Remove(BiometricKeyStorageKey);
                    throw;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
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
            TotpBiometricKeyRecord? biometricRecord = null;
            try
            {
                encryptedMasterKey = TotpKeyFileFormat.Encrypt(masterKey, newPassword);
                var stored = await SecureStorage.Default.GetAsync(BiometricKeyStorageKey).ConfigureAwait(false);
                if (TotpBiometricKeyRecord.TryParse(stored, out var record) && record is not null &&
                    record.MatchesMasterKey(masterKey))
                    biometricRecord = record;
            }
            finally { CryptographicOperations.ZeroMemory(masterKey); }
            await _secureFileService.WriteAllBytesAsync(_keyFilePath, encryptedMasterKey);
            if (biometricRecord is not null)
            {
                try
                {
                    biometricRecord.RebindKeyFile(encryptedMasterKey);
                    await SecureStorage.Default.SetAsync(BiometricKeyStorageKey, biometricRecord.Serialize()).ConfigureAwait(false);
                }
                catch
                {
                    // The password change is committed; stale biometric access must fail closed.
                    SecureStorage.Default.Remove(BiometricKeyStorageKey);
                }
            }
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
        Locked?.Invoke(this, EventArgs.Empty);
    }

    public event EventHandler? Locked;

    internal long LockGeneration { get { lock (_keyStateLock) return _lockGeneration; } }

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

            _secureFileService.Delete(_keyFilePath);

            // Clear password preferences and metadata
            SecureStorage.Default.Remove(BiometricKeyStorageKey);
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

    private void EnsureStillUnlocked(byte[] key, long generation)
    {
        lock (_keyStateLock)
        {
            if (!_isUnlocked || _unlockedKey is null || _lockGeneration != generation ||
                !CryptographicOperations.FixedTimeEquals(_unlockedKey, key))
                throw new OperationCanceledException("Der Authenticator wurde während der Biometrie-Einrichtung gesperrt.");
        }
    }

    private async Task VerifyDataFileAsync(byte[] key, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_dataFilePath)) return;
        var encrypted = await File.ReadAllBytesAsync(_dataFilePath, cancellationToken).ConfigureAwait(false);
        var plain = DecryptWithKey(encrypted, key);
        try
        {
            if (plain.Length == 0)
                throw new InvalidDataException("Die Authenticator-Datei enthält keinen gültigen Snapshot.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
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
            try
            {
                using var aes = new AesGcm(key, tag.Length);
                aes.Decrypt(nonce, cipher, tag, plain);
                return plain;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plain);
                throw;
            }
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
