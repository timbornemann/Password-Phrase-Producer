using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Password_Phrase_Producer.Services.Security;

// The password metadata and encrypted master key must be one atomic file. A
// password change can otherwise leave the file and SecureStorage out of sync.
public static class TotpKeyFileFormat
{
    private static ReadOnlySpan<byte> Header => "TOTP\x02"u8;
    private const int SaltLength = 16;
    private const int VerifierLength = 32;
    private const int NonceLength = 12;
    private const int MasterKeyLength = 32;
    private const int TagLength = 16;
    private const int Iterations = 200_000;
    private const int HeaderLength = 5;
    private const int FileLength = HeaderLength + SaltLength + sizeof(int) + VerifierLength + NonceLength + MasterKeyLength + TagLength;

    public static bool IsV2(ReadOnlySpan<byte> file) => file.StartsWith(Header);

    public static byte[] Encrypt(byte[] masterKey, string password)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        if (masterKey.Length != MasterKeyLength)
            throw new ArgumentException("Ungültige Authenticator-Schlüssellänge.", nameof(masterKey));

        var file = new byte[FileLength];
        Header.CopyTo(file);
        var salt = file.AsSpan(HeaderLength, SaltLength);
        RandomNumberGenerator.Fill(salt);
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(HeaderLength + SaltLength, sizeof(int)), Iterations);
        var derivedKey = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, MasterKeyLength);
        try
        {
            var verifierOffset = HeaderLength + SaltLength + sizeof(int);
            SHA256.HashData(derivedKey, file.AsSpan(verifierOffset, VerifierLength));
            var nonceOffset = verifierOffset + VerifierLength;
            var nonce = file.AsSpan(nonceOffset, NonceLength);
            RandomNumberGenerator.Fill(nonce);
            using var aes = new AesGcm(derivedKey, TagLength);
            aes.Encrypt(nonce, masterKey, file.AsSpan(nonceOffset + NonceLength, MasterKeyLength), file.AsSpan(nonceOffset + NonceLength + MasterKeyLength, TagLength));
            return file;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derivedKey);
        }
    }

    public static bool TryDecrypt(ReadOnlySpan<byte> file, string password, out byte[]? masterKey)
    {
        masterKey = null;
        if (!IsV2(file) || file.Length != FileLength || string.IsNullOrEmpty(password))
            return false;

        var salt = file.Slice(HeaderLength, SaltLength);
        var iterations = BinaryPrimitives.ReadInt32LittleEndian(file.Slice(HeaderLength + SaltLength, sizeof(int)));
        if (iterations is < 10_000 or > 1_000_000)
            return false;

        var derivedKey = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, MasterKeyLength);
        try
        {
            var verifierOffset = HeaderLength + SaltLength + sizeof(int);
            Span<byte> actualVerifier = stackalloc byte[VerifierLength];
            SHA256.HashData(derivedKey, actualVerifier);
            if (!CryptographicOperations.FixedTimeEquals(actualVerifier, file.Slice(verifierOffset, VerifierLength)))
                return false;

            var nonceOffset = verifierOffset + VerifierLength;
            var decrypted = new byte[MasterKeyLength];
            try
            {
                using var aes = new AesGcm(derivedKey, TagLength);
                aes.Decrypt(file.Slice(nonceOffset, NonceLength),
                    file.Slice(nonceOffset + NonceLength, MasterKeyLength),
                    file.Slice(nonceOffset + NonceLength + MasterKeyLength, TagLength), decrypted);
                masterKey = decrypted;
                return true;
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(decrypted);
                return false;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derivedKey);
        }
    }
}
