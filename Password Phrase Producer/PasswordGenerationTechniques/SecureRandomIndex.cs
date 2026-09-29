using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Password_Phrase_Producer.PasswordGenerationTechniques;

// A seed provides reproducibility, not entropy. Without a seed every draw uses the OS CSPRNG.
internal sealed class SecureRandomIndex : IDisposable
{
    private readonly byte[]? _key;
    private readonly byte[] _block = new byte[32];
    private int _offset = 32;
    private ulong _counter;

    public SecureRandomIndex(string? seed, string purpose)
    {
        if (!string.IsNullOrWhiteSpace(seed))
        {
            _key = SHA256.HashData(Encoding.UTF8.GetBytes($"PasswordPhraseProducer/{purpose}/v1/{seed}"));
        }
    }

    public int Next(int exclusiveUpperBound)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(exclusiveUpperBound);
        if (_key is null)
        {
            return RandomNumberGenerator.GetInt32(exclusiveUpperBound);
        }

        var bound = (uint)exclusiveUpperBound;
        const ulong range = 1UL << 32;
        var limit = range - range % bound;
        Span<byte> counter = stackalloc byte[8];
        uint value;
        do
        {
            if (_offset == _block.Length)
            {
                BinaryPrimitives.WriteUInt64BigEndian(counter, _counter++);
                HMACSHA256.HashData(_key, counter, _block);
                _offset = 0;
            }

            value = BinaryPrimitives.ReadUInt32LittleEndian(_block.AsSpan(_offset, 4));
            _offset += 4;
        } while (value >= limit);

        return (int)(value % bound);
    }

    public void Dispose()
    {
        if (_key is not null) CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_block);
    }
}
