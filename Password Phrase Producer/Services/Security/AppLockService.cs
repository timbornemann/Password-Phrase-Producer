using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Password_Phrase_Producer.Services.Security;

public interface IAppLockService
{
    bool IsUnlocked { get; }
    Task<bool> IsConfiguredAsync();
    Task<bool> UnlockAsync(string password);
    Task<bool> UnlockWithBiometricsAsync();
    Task SetupAsync(string password, bool enableBiometrics);
    Task ChangePasswordAsync(string currentPassword, string newPassword);
    void Lock();
    byte[] GetMasterKey(); // Throws if locked
    Task EnableBiometricsAsync(bool enable);
    Task<bool> IsBiometricConfiguredAsync();
    void OnAppBackgrounded();
    bool CheckLockTimeout();
}

public class AppLockService : IAppLockService
{
    private const string AppLockStorageKey = "AppLockMetadata_V1";
    private const int AuthTagLength = 16;
    private const int KeySize = 32; // 256 bits
    private const int NonceSize = 12; // 96 bits
    
    private readonly IBiometricAuthenticationService _biometricService;
    private byte[]? _masterKey;
    private AppLockMetadata? _cachedMetadata;
    private DateTime? _lastBackgroundTime;
    private readonly TimeSpan _lockTimeout = TimeSpan.FromMinutes(5);

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
        await LoadMetadataIfNeededAsync().ConfigureAwait(false);
        if (_cachedMetadata == null) return false;

        var salt = Convert.FromBase64String(_cachedMetadata.Salt);
        var iterations = _cachedMetadata.Iterations;
        
        using var derivedKey = DeriveKey(password, salt, iterations);
        
        // Verify Password
        var actualVerifier = CreateVerifier(derivedKey.GetBytes(KeySize));
        var expectedVerifier = Convert.FromBase64String(_cachedMetadata.Verifier);
        
        if (!CryptographicOperations.FixedTimeEquals(actualVerifier, expectedVerifier))
        {
            return false;
        }

        // Decrypt Master Key
        try 
        {
            var kek = DeriveKeyBytes(password, salt, iterations); // Key Encryption Key
            var encryptedMek = Convert.FromBase64String(_cachedMetadata.EncryptedMasterKey);
            
            _masterKey = DecryptAesGcm(encryptedMek, kek);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> UnlockWithBiometricsAsync()
    {
        await LoadMetadataIfNeededAsync().ConfigureAwait(false);
        if (_cachedMetadata == null || string.IsNullOrEmpty(_cachedMetadata.BiometricEncryptedMasterKey))
        {
            return false;
        }

        try
        {
            var encryptedMek = Convert.FromBase64String(_cachedMetadata.BiometricEncryptedMasterKey);
            _masterKey = await _biometricService.DecryptAsync(encryptedMek);
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

    public async Task SetupAsync(string password, bool enableBiometrics)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        // Generate new Master Encryption Key (MEK)
        var mek = RandomNumberGenerator.GetBytes(KeySize);
        
        // Generate Salt
        var salt = RandomNumberGenerator.GetBytes(16);
        var iterations = 200_000;

        // Derive KEK (Key Encryption Key)
        var kek = DeriveKeyBytes(password, salt, iterations);
        
        // Create Verifier
        var verifier = CreateVerifier(kek);

        // Encrypt MEK with KEK
        var encryptedMek = EncryptAesGcm(mek, kek);

        var metadata = new AppLockMetadata
        {
            Salt = Convert.ToBase64String(salt),
            Iterations = iterations,
            Verifier = Convert.ToBase64String(verifier),
            EncryptedMasterKey = Convert.ToBase64String(encryptedMek),
            BiometricEncryptedMasterKey = null
        };

        _cachedMetadata = metadata;
        _masterKey = mek; // Logged in immediately
        
        // Save initial metadata
        var json = JsonSerializer.Serialize(metadata);
        await SecureStorage.Default.SetAsync(AppLockStorageKey, json).ConfigureAwait(false);

        // Enable biometrics if requested
        if (enableBiometrics)
        {
            await EnableBiometricsAsync(true).ConfigureAwait(false);
        }
    }

    public async Task ChangePasswordAsync(string currentPassword, string newPassword)
    {
        if (!IsUnlocked || _masterKey == null)
        {
            // If not unlocked, try to unlock first (this requires currentPassword is correct)
            if (!await UnlockAsync(currentPassword))
            {
                throw new UnauthorizedAccessException("Current password incorrect.");
            }
        }
        
        // Generate new Salt/KEK for new password
        var salt = RandomNumberGenerator.GetBytes(16);
        var iterations = 200_000;
        var kek = DeriveKeyBytes(newPassword, salt, iterations);
        var verifier = CreateVerifier(kek);
        
        // Re-encrypt EXISTING MEK with new KEK
        var encryptedMek = EncryptAesGcm(_masterKey, kek);
        
        if (_cachedMetadata == null) await LoadMetadataIfNeededAsync();

        var newMetadata = new AppLockMetadata
        {
            Salt = Convert.ToBase64String(salt),
            Iterations = iterations,
            Verifier = Convert.ToBase64String(verifier),
            EncryptedMasterKey = Convert.ToBase64String(encryptedMek),
            BiometricEncryptedMasterKey = _cachedMetadata?.BiometricEncryptedMasterKey
        };

        var json = JsonSerializer.Serialize(newMetadata);
        await SecureStorage.Default.SetAsync(AppLockStorageKey, json).ConfigureAwait(false);
        _cachedMetadata = newMetadata;
    }

    public async Task EnableBiometricsAsync(bool enable)
    {
        if (!IsUnlocked || _masterKey == null) throw new InvalidOperationException("Must be unlocked.");
        
        if (_cachedMetadata == null) await LoadMetadataIfNeededAsync();
        if (_cachedMetadata == null) throw new InvalidOperationException("No metadata found.");

        if (enable)
        {
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

    public async Task<bool> IsBiometricConfiguredAsync()
    {
        await LoadMetadataIfNeededAsync().ConfigureAwait(false);
        return !string.IsNullOrEmpty(_cachedMetadata?.BiometricEncryptedMasterKey);
    }

    public void OnAppBackgrounded()
    {
        if (IsUnlocked) // Only track if currently unlocked
        {
            _lastBackgroundTime = DateTime.UtcNow;
        }
    }

    public bool CheckLockTimeout()
    {
        if (_lastBackgroundTime == null) return false;

        var elapsed = DateTime.UtcNow - _lastBackgroundTime.Value;
        if (elapsed > _lockTimeout)
        {
            _lastBackgroundTime = null; // Reset
            return true; // Should lock
        }
        
        _lastBackgroundTime = null; // Reset on successful check (activity resumed)
        return false;
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
        return _masterKey;
    }

    private async Task LoadMetadataIfNeededAsync()
    {
        if (_cachedMetadata != null) return;
        
        var json = await SecureStorage.Default.GetAsync(AppLockStorageKey).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(json))
        {
            _cachedMetadata = JsonSerializer.Deserialize<AppLockMetadata>(json);
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

    private class AppLockMetadata
    {
        public string Salt { get; set; } = ""; // Base64
        public int Iterations { get; set; }
        public string Verifier { get; set; } = ""; // Base64 (Hash of KEK)
        public string EncryptedMasterKey { get; set; } = ""; // Base64 (MEK encrypted with KEK)
        public string? BiometricEncryptedMasterKey { get; set; } // Base64 (MEK encrypted with Bio)
    }
}
