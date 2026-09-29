using System.Text;

namespace Password_Phrase_Producer.Services.Synchronization;

internal static class SyncFileReader
{
    internal const int MaxJsonBytes = 64 * 1024 * 1024;
    private static readonly byte[] Magic = "PPP1"u8.ToArray();

    internal static async Task<string> ReadJsonAsync(Stream stream, int maxBytes = MaxJsonBytes,
        CancellationToken cancellationToken = default)
    {
        var prefix = new byte[4];
        if (await ReadExactlyAsync(stream, prefix, cancellationToken).ConfigureAwait(false) != prefix.Length)
            throw new InvalidDataException("Sync file is empty or truncated.");

        if (prefix.AsSpan().SequenceEqual(Magic))
        {
            var lengthBytes = new byte[4];
            if (await ReadExactlyAsync(stream, lengthBytes, cancellationToken).ConfigureAwait(false) != lengthBytes.Length)
                throw new InvalidDataException("Sync file length is missing.");
            var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
            if (length <= 0 || length > maxBytes)
                throw new InvalidDataException("Sync file length is invalid.");
            var content = new byte[length];
            if (await ReadExactlyAsync(stream, content, cancellationToken).ConfigureAwait(false) != length)
                throw new InvalidDataException("Sync file is truncated.");
            return Encoding.UTF8.GetString(content);
        }

        // Older files contain JSON without a frame. Bound these reads as well.
        using var output = new MemoryStream();
        output.Write(prefix);
        var buffer = new byte[8192];
        int count;
        while ((count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
        {
            if (output.Length + count > maxBytes)
                throw new InvalidDataException("Sync file is too large.");
            output.Write(buffer, 0, count);
        }
        return Encoding.UTF8.GetString(output.GetBuffer(), 0, checked((int)output.Length));
    }

    private static async Task<int> ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken).ConfigureAwait(false);
            if (count == 0) break;
            read += count;
        }
        return read;
    }
}
