using System.Text;
using Password_Phrase_Producer.Services.Synchronization;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class SyncFileReaderTests
{
    [Fact]
    public async Task FramedFileReadsFromNonSeekableStream()
    {
        var json = "{\"header\":{}}";
        var bytes = "PPP1"u8.ToArray()
            .Concat(BitConverter.GetBytes(Encoding.UTF8.GetByteCount(json)))
            .Concat(Encoding.UTF8.GetBytes(json)).ToArray();
        using var stream = new NonSeekableStream(bytes);
        Assert.Equal(json, await SyncFileReader.ReadJsonAsync(stream, 1024));
    }

    [Fact]
    public async Task RejectsOversizedAndTruncatedFramesBeforeAllocating()
    {
        var oversized = "PPP1"u8.ToArray().Concat(BitConverter.GetBytes(1025)).ToArray();
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            SyncFileReader.ReadJsonAsync(new MemoryStream(oversized), 1024));
        var truncated = "PPP1"u8.ToArray().Concat(BitConverter.GetBytes(10)).Concat("{}"u8.ToArray()).ToArray();
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            SyncFileReader.ReadJsonAsync(new MemoryStream(truncated), 1024));
    }

    [Fact]
    public async Task LegacyJsonIsAlsoSizeLimited()
    {
        using var stream = new NonSeekableStream(Encoding.UTF8.GetBytes("{\"more\":\"data\"}"));
        await Assert.ThrowsAsync<InvalidDataException>(() => SyncFileReader.ReadJsonAsync(stream, 8));
    }

    private sealed class NonSeekableStream(byte[] data) : MemoryStream(data)
    {
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin loc) => throw new NotSupportedException();
    }
}
