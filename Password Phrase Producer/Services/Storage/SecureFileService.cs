using PasswordPhraseProducer.Updates;
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
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (_appLockService.IsUnlocked)
            {
                var masterKey = _appLockService.GetMasterKey();
                try
                {
                    var encrypted = Encrypt(bytes, masterKey);
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    await AtomicFile.WriteAsync(path, encrypted, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(masterKey);
                }
            }
            else
            {
                throw new InvalidOperationException("Cannot write a secure file while App Lock is locked or unconfigured.");
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public async Task<byte[]> ReadAllBytesAsync(string path, CancellationToken cancellationToken = default)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (!File.Exists(path)) return Array.Empty<byte>();

            if (_appLockService.IsUnlocked)
            {
                var fileContent = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);

                try
                {
                    var masterKey = _appLockService.GetMasterKey();
                    try { return Decrypt(fileContent, masterKey); }
                    finally { CryptographicOperations.ZeroMemory(masterKey); }
                }
                catch (Exception ex)
                {
                    // No migration fallback. If decryption fails, it's an error.
                    throw new InvalidOperationException("Failed to decrypt secure file.", ex);
                }
            }

            throw new InvalidOperationException("Cannot read a secure file while App Lock is locked or unconfigured.");
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public Task<bool> ExistsAsync(string path)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            return Task.FromResult(File.Exists(path));
        }
        catch
        {
            dataOperation.Failed();
            throw;
        }
    }

    public void Delete(string path)
    {
        using var dataOperation = AppDataOperations.Shared.BeginOperation();
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            dataOperation.Failed();
            throw;
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
