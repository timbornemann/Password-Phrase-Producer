using PasswordPhraseProducer.Updates;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Password_Phrase_Producer.Services.Security;

public interface IAppLockService
{
    bool IsUnlocked { get; }
    Task<bool> IsConfiguredAsync();
    Task<bool> UnlockAsync(string password);
    Task<bool> VerifyPasswordAsync(string password);
    Task<bool> UnlockWithBiometricsAsync();
    Task SetupAsync(string password, bool enableBiometrics);
    Task ChangePasswordAsync(string currentPassword, string newPassword);
    void Lock();
    byte[] GetMasterKey(); // Throws if locked
    Task EnableBiometricsAsync(bool enable);
    Task<bool> IsBiometricConfiguredAsync();
    byte[] EncryptWithMasterKey(byte[] data);
    byte[] DecryptWithMasterKey(byte[] data);
}

public class AppLockService : IAppLockService
{
    private const string AppLockStorageKey = "AppLockMetadata_V1";
    private const int AuthTagLength = 16;
    private const int KeySize = 32; // 256 bits
    private const int NonceSize = 12; // 96 bits
    private const int NewPbkdf2Iterations = 600_000;

    private readonly IBiometricAuthenticationService _biometricService;
    private byte[]? _masterKey;
    private AppLockMetadata? _cachedMetadata;

    public bool IsUnlocked => _masterKey != null;

    public AppLockService(IBiometricAuthenticationService biometricService)
    {
        _biometricService = biometricService;
    }

    public async Task<bool> IsConfiguredAsync()
    {
        if (_cachedMetadata != null) return true;
        var json = await SecureStorage.Default.GetAsync(AppLockStorageKey).ConfigureAwait(false);
        return !string.IsNullOrEmpty(json);
    }

    public async Task InitializeAsync()
    {
        await LoadMetadataIfNeededAsync().ConfigureAwait(false);
    }

    public async Task<bool> UnlockAsync(string password)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            await LoadMetadataIfNeededAsync().ConfigureAwait(false);
            if (_cachedMetadata == null) return false;

            var salt = Convert.FromBase64String(_cachedMetadata.Salt);
            var iterations = _cachedMetadata.Iterations;
            if (salt.Length != 16 || iterations is < 10_000 or > 1_000_000) return false;

            var kek = DeriveKeyBytes(password, salt, iterations);
            try
            {
                var actualVerifier = CreateVerifier(kek);
                var expectedVerifier = Convert.FromBase64String(_cachedMetadata.Verifier);
                if (!CryptographicOperations.FixedTimeEquals(actualVerifier, expectedVerifier))
                    return false;

                var encryptedMek = Convert.FromBase64String(_cachedMetadata.EncryptedMasterKey);

                var masterKey = DecryptAesGcm(encryptedMek, kek);
                if (masterKey.Length != KeySize)
                {
                    CryptographicOperations.ZeroMemory(masterKey);
                    return false;
                }

                // The authenticated password wrapper is authoritative. Repair a
                // missing or damaged biometric verifier after successful decryption.
                if (!MatchesMasterKeyVerifier(masterKey) || string.IsNullOrEmpty(_cachedMetadata.MasterKeyVerifier))
                {
                    var previousVerifier = _cachedMetadata.MasterKeyVerifier;
                    var verifier = Convert.ToBase64String(CreateVerifier(masterKey));
                    _cachedMetadata.MasterKeyVerifier = verifier;
                    try
                    {
                        await SecureStorage.Default.SetAsync(AppLockStorageKey, JsonSerializer.Serialize(_cachedMetadata))
                            .ConfigureAwait(false);
                    }
                    catch
                    {
                        _cachedMetadata.MasterKeyVerifier = previousVerifier;
                    }
                }
                Lock();
                _masterKey = masterKey;
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek);
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<bool> VerifyPasswordAsync(string password)
    {
        if (string.IsNullOrWhiteSpace(password)) return false;
        await LoadMetadataIfNeededAsync().ConfigureAwait(false);
        if (_cachedMetadata is null) return false;

        byte[]? kek = null;
        byte[]? masterKey = null;
        try
        {
            var salt = Convert.FromBase64String(_cachedMetadata.Salt);
            var expectedVerifier = Convert.FromBase64String(_cachedMetadata.Verifier);
            if (salt.Length != 16 || expectedVerifier.Length != 32 ||
                _cachedMetadata.Iterations is < 10_000 or > 1_000_000) return false;

            kek = DeriveKeyBytes(password, salt, _cachedMetadata.Iterations);
            var actualVerifier = CreateVerifier(kek);
            if (!CryptographicOperations.FixedTimeEquals(actualVerifier, expectedVerifier)) return false;

            masterKey = DecryptAesGcm(Convert.FromBase64String(_cachedMetadata.EncryptedMasterKey), kek);
            return masterKey.Length == KeySize;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or InvalidDataException or ArgumentException)
        {
            return false;
        }
        finally
        {
            if (kek is not null) CryptographicOperations.ZeroMemory(kek);
            if (masterKey is not null) CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    public async Task<bool> UnlockWithBiometricsAsync()
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            await LoadMetadataIfNeededAsync().ConfigureAwait(false);
            if (_cachedMetadata == null || string.IsNullOrEmpty(_cachedMetadata.BiometricEncryptedMasterKey))
            {
                return false;
            }

            try
            {
                var encryptedMek = Convert.FromBase64String(_cachedMetadata.BiometricEncryptedMasterKey);
                var masterKey = await _biometricService.DecryptAsync(encryptedMek);
                if (masterKey.Length != KeySize || string.IsNullOrEmpty(_cachedMetadata.MasterKeyVerifier) ||
                    !MatchesMasterKeyVerifier(masterKey))
                {
                    CryptographicOperations.ZeroMemory(masterKey);
                    return false;
                }
                Lock();
                _masterKey = masterKey;
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
                // User cancelled or failed bio
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

    public async Task SetupAsync(string password, bool enableBiometrics)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            await LoadMetadataIfNeededAsync().ConfigureAwait(false);
            if (_cachedMetadata is not null)
                throw new InvalidOperationException("App lock is already configured.");
            NewPasswordPolicy.Validate(password, nameof(password));

            // Generate new Master Encryption Key (MEK)
            var mek = RandomNumberGenerator.GetBytes(KeySize);

            // Generate Salt
            var salt = RandomNumberGenerator.GetBytes(16);
            var iterations = NewPbkdf2Iterations;

            // Derive KEK (Key Encryption Key)
            var kek = DeriveKeyBytes(password, salt, iterations);
            try
            {
                var verifier = CreateVerifier(kek);
                var encryptedMek = EncryptAesGcm(mek, kek);
                var metadata = new AppLockMetadata
                {
                    Salt = Convert.ToBase64String(salt),
                    Iterations = iterations,
                    Verifier = Convert.ToBase64String(verifier),
                    EncryptedMasterKey = Convert.ToBase64String(encryptedMek),
                    MasterKeyVerifier = Convert.ToBase64String(CreateVerifier(mek)),
                    BiometricEncryptedMasterKey = null
                };

                await SecureStorage.Default.SetAsync(AppLockStorageKey, JsonSerializer.Serialize(metadata)).ConfigureAwait(false);
                _cachedMetadata = metadata;
                _masterKey = mek;
                if (enableBiometrics)
                    await EnableBiometricsAsync(true).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek);
                if (!ReferenceEquals(_masterKey, mek)) CryptographicOperations.ZeroMemory(mek);
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task ChangePasswordAsync(string currentPassword, string newPassword)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(currentPassword);
            NewPasswordPolicy.Validate(newPassword, nameof(newPassword));
            await LoadMetadataIfNeededAsync().ConfigureAwait(false);
            if (_cachedMetadata is null)
                throw new InvalidOperationException("App lock is not configured.");

            var oldSalt = Convert.FromBase64String(_cachedMetadata.Salt);
            if (oldSalt.Length != 16 || _cachedMetadata.Iterations is < 10_000 or > 1_000_000)
                throw new InvalidDataException("Ungültige App-Schlüsselableitung.");
            var oldKek = DeriveKeyBytes(currentPassword, oldSalt, _cachedMetadata.Iterations);
            try
            {
                var expectedVerifier = Convert.FromBase64String(_cachedMetadata.Verifier);
                var actualVerifier = CreateVerifier(oldKek);
                if (!CryptographicOperations.FixedTimeEquals(actualVerifier, expectedVerifier))
                    throw new UnauthorizedAccessException("Current password incorrect.");

                if (_masterKey is null)
                {
                    var oldEncryptedMek = Convert.FromBase64String(_cachedMetadata.EncryptedMasterKey);
                    _masterKey = DecryptAesGcm(oldEncryptedMek, oldKek);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(oldKek);
            }

            // Generate new Salt/KEK for new password
            var salt = RandomNumberGenerator.GetBytes(16);
            var iterations = NewPbkdf2Iterations;
            var kek = DeriveKeyBytes(newPassword, salt, iterations);
            try
            {
                var verifier = CreateVerifier(kek);
                var encryptedMek = EncryptAesGcm(_masterKey, kek);
                var newMetadata = new AppLockMetadata
                {
                    Salt = Convert.ToBase64String(salt),
                    Iterations = iterations,
                    Verifier = Convert.ToBase64String(verifier),
                    EncryptedMasterKey = Convert.ToBase64String(encryptedMek),
                    MasterKeyVerifier = Convert.ToBase64String(CreateVerifier(_masterKey)),
                    BiometricEncryptedMasterKey = _cachedMetadata?.BiometricEncryptedMasterKey
                };

                await SecureStorage.Default.SetAsync(AppLockStorageKey, JsonSerializer.Serialize(newMetadata)).ConfigureAwait(false);
                _cachedMetadata = newMetadata;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek);
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task EnableBiometricsAsync(bool enable)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (!IsUnlocked || _masterKey == null) throw new InvalidOperationException("Must be unlocked.");

            if (_cachedMetadata == null) await LoadMetadataIfNeededAsync();
            if (_cachedMetadata == null) throw new InvalidOperationException("No metadata found.");

            if (enable)
            {
                _cachedMetadata.MasterKeyVerifier = Convert.ToBase64String(CreateVerifier(_masterKey));
                var bioEncryptedMek = await _biometricService.EncryptAsync(_masterKey);
                _cachedMetadata.BiometricEncryptedMasterKey = Convert.ToBase64String(bioEncryptedMek);
            }
            else
            {
                _cachedMetadata.BiometricEncryptedMasterKey = null;
            }

            var json = JsonSerializer.Serialize(_cachedMetadata);
            await SecureStorage.Default.SetAsync(AppLockStorageKey, json).ConfigureAwait(false);
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<bool> IsBiometricConfiguredAsync()
    {
        await LoadMetadataIfNeededAsync().ConfigureAwait(false);
        return !string.IsNullOrEmpty(_cachedMetadata?.BiometricEncryptedMasterKey);
    }

    public void Lock()
    {
        if (_masterKey != null)
        {
            Array.Clear(_masterKey);
            _masterKey = null;
        }
    }

    public byte[] GetMasterKey()
    {
        if (_masterKey == null) throw new InvalidOperationException("App is locked.");
        return _masterKey.ToArray();
    }

    private async Task LoadMetadataIfNeededAsync()
    {
        if (_cachedMetadata != null) return;

        var json = await SecureStorage.Default.GetAsync(AppLockStorageKey).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(json))
        {
            _cachedMetadata = JsonSerializer.Deserialize<AppLockMetadata>(json);
#if IOS || MACCATALYST
            // Older versions stored the raw master key as the "biometric ciphertext".
            if (_cachedMetadata?.BiometricEncryptedMasterKey is not null)
            {
                _cachedMetadata.BiometricEncryptedMasterKey = null;
                await SecureStorage.Default.SetAsync(AppLockStorageKey, JsonSerializer.Serialize(_cachedMetadata))
                    .ConfigureAwait(false);
            }
#endif
        }
    }

    private static Rfc2898DeriveBytes DeriveKey(string password, byte[] salt, int iterations)
    {
        return new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
    }

    private static byte[] DeriveKeyBytes(string password, byte[] salt, int iterations)
    {
        using var kdf = DeriveKey(password, salt, iterations);
        return kdf.GetBytes(KeySize);
    }

    private static byte[] CreateVerifier(byte[] key)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(key);
    }

    private bool MatchesMasterKeyVerifier(byte[] masterKey)
    {
        if (string.IsNullOrEmpty(_cachedMetadata?.MasterKeyVerifier)) return true;
        try
        {
            var expected = Convert.FromBase64String(_cachedMetadata.MasterKeyVerifier);
            return expected.Length == 32 &&
                   CryptographicOperations.FixedTimeEquals(expected, CreateVerifier(masterKey));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] EncryptAesGcm(byte[] plaintext, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AuthTagLength];

        using var aes = new AesGcm(key, AuthTagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Format: Nonce + Tag + Ciphertext
        var result = new byte[NonceSize + AuthTagLength + plaintext.Length];
        System.Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        System.Buffer.BlockCopy(tag, 0, result, NonceSize, AuthTagLength);
        System.Buffer.BlockCopy(ciphertext, 0, result, NonceSize + AuthTagLength, ciphertext.Length);

        return result;
    }

    private static byte[] DecryptAesGcm(byte[] data, byte[] key)
    {
        // Format: Nonce + Tag + Ciphertext
        if (data.Length < NonceSize + AuthTagLength) throw new ArgumentException("Invalid data");

        var nonce = new byte[NonceSize];
        var tag = new byte[AuthTagLength];
        var cipherLength = data.Length - NonceSize - AuthTagLength;
        var ciphertext = new byte[cipherLength];

        System.Buffer.BlockCopy(data, 0, nonce, 0, NonceSize);
        System.Buffer.BlockCopy(data, NonceSize, tag, 0, AuthTagLength);
        System.Buffer.BlockCopy(data, NonceSize + AuthTagLength, ciphertext, 0, cipherLength);

        var plaintext = new byte[cipherLength];
        using var aes = new AesGcm(key, AuthTagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }

    public byte[] EncryptWithMasterKey(byte[] data)
    {
        var key = GetMasterKey();
        try { return EncryptAesGcm(data, key); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    public byte[] DecryptWithMasterKey(byte[] data)
    {
        var key = GetMasterKey();
        try { return DecryptAesGcm(data, key); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private class AppLockMetadata
    {
        public string Salt { get; set; } = ""; // Base64
        public int Iterations { get; set; }
        public string Verifier { get; set; } = ""; // Base64 (Hash of KEK)
        public string EncryptedMasterKey { get; set; } = ""; // Base64 (MEK encrypted with KEK)
        public string? MasterKeyVerifier { get; set; } // SHA-256 of random MEK; checks biometric output
        public string? BiometricEncryptedMasterKey { get; set; } // Base64 (MEK encrypted with Bio)
    }
}
