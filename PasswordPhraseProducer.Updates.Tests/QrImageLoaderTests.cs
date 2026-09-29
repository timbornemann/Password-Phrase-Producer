using Password_Phrase_Producer.Services.Qr;
using SkiaSharp;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class QrImageLoaderTests
{
    [Fact]
    public void LoadsOrdinaryImage()
    {
        using var bitmap = new SKBitmap(32, 32);
        bitmap.Erase(SKColors.White);
        bitmap.SetPixel(4, 4, SKColors.Black);
        using var encoded = bitmap.Encode(SKEncodedImageFormat.Png, 100);
        using var stream = new MemoryStream(encoded.ToArray());

        var image = QrImageLoader.Load(stream);

        Assert.NotNull(image);
        Assert.Equal(32, image.Value.Width);
        Assert.Equal(32, image.Value.Height);
    }

    [Fact]
    public void RejectsEncodedImageAboveLimit()
    {
        using var stream = new MemoryStream(new byte[16 * 1024 * 1024 + 1]);

        Assert.Throws<InvalidDataException>(() => QrImageLoader.Load(stream));
    }
}
