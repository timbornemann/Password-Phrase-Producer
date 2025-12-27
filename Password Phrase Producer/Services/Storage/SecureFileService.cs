using System.Security.Cryptography;

namespace Password_Phrase_Producer.Services.Storage;

public interface ISecureFileService
{
    Task WriteAllBytesAsync(string path, byte[] bytes, CancellationToken cancellationToken = default);
    Task<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken = default);
    Task<bool> ExistsAsync(string path);
    void Delete(string path);
}

public class SecureFileService : ISecureFileService
{
    private readonly Services.Security.IAppLockService _appLockService;
    private const int NonceSize = 12;
    private const int AuthTagLength = 16;
    private const int HeaderSize = NonceSize + AuthTagLength;

    public SecureFileService(Services.Security.IAppLockService appLockService)
    {
        _appLockService = appLockService;
    }

    public async Task WriteAllBytesAsync(string path, byte[] bytes, CancellationToken cancellationToken = default)
    {
        if (_appLockService.IsUnlocked)
        {
            var masterKey = _appLockService.GetMasterKey();
            var encrypted = Encrypt(bytes, masterKey);
            
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllBytesAsync(path, encrypted, cancellationToken).ConfigureAwait(false);
        }
        else if (await _appLockService.IsConfiguredAsync().ConfigureAwait(false))
        {
             // Configured but locked -> Error
             throw new InvalidOperationException("Cannot write secure file while App Lock is locked.");
        }
        else
        {
            // Not configured (Fresh install) -> Write plain
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllBytesAsync(path, bytes, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(path)) return Array.Empty<byte>();
        
        // If configured, require encryption (or valid unlock)
        if (await _appLockService.IsConfiguredAsync().ConfigureAwait(false))
        {
            if (!_appLockService.IsUnlocked)
            {
                // Cannot decrypt.
                 throw new InvalidOperationException("Cannot read secure file while App Lock is locked.");
            }

            var fileContent = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            
            try 
            {
                var masterKey = _appLockService.GetMasterKey();
                return Decrypt(fileContent, masterKey);
            }
            catch (Exception ex)
            {
                // No migration fallback. If decryption fails, it's an error.
                throw new InvalidOperationException("Failed to decrypt secure file.", ex);
            }
        }
        
        // Not configured: Assume plain.
        return await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public Task<bool> ExistsAsync(string path)
    {
        return Task.FromResult(File.Exists(path));
    }

    public void Delete(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static byte[] Encrypt(byte[] plaintext, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AuthTagLength];

        using var aes = new AesGcm(key, AuthTagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var result = new byte[NonceSize + AuthTagLength + plaintext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, result, NonceSize, AuthTagLength);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize + AuthTagLength, ciphertext.Length);

        return result;
    }

    private static byte[] Decrypt(byte[] data, byte[] key)
    {
        if (data.Length < HeaderSize) throw new ArgumentException("Invalid encrypted data size");

        var nonce = new byte[NonceSize];
        var tag = new byte[AuthTagLength];
        var cipherSize = data.Length - HeaderSize;
        var ciphertext = new byte[cipherSize];

        Buffer.BlockCopy(data, 0, nonce, 0, NonceSize);
        Buffer.BlockCopy(data, NonceSize, tag, 0, AuthTagLength);
        Buffer.BlockCopy(data, HeaderSize, ciphertext, 0, cipherSize);

        var plaintext = new byte[cipherSize];
        using var aes = new AesGcm(key, AuthTagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext; // Success
    }
}
