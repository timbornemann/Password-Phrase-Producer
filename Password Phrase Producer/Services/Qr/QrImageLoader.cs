using SkiaSharp;

namespace Password_Phrase_Producer.Services.Qr;

/// <summary>
/// Loads screenshots or photos as grayscale images for <see cref="QrCodeDecoder"/>.
/// </summary>
public static class QrImageLoader
{
    private const int MaxDimension = 3000;
    private const int MaxSourceDimension = 10000;
    private const long MaxSourcePixels = 20_000_000;
    private const int MaxEncodedBytes = 16 * 1024 * 1024;

    public static GrayImage? Load(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        // Picker streams may be non-seekable. Bound the encoded input before a native
        // decoder sees it, then inspect its dimensions before allocating a bitmap.
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int count;
        while ((count = stream.Read(chunk, 0, Math.Min(chunk.Length, MaxEncodedBytes + 1 - (int)buffer.Length))) > 0)
        {
            buffer.Write(chunk, 0, count);
            if (buffer.Length > MaxEncodedBytes)
            {
                throw new InvalidDataException("Das QR-Bild ist zu groß.");
            }
        }

        using var data = SKData.CreateCopy(buffer.ToArray());
        using var codec = SKCodec.Create(data);
        if (codec is null)
        {
            return null;
        }

        var info = codec.Info;
        if (info.Width <= 0 || info.Height <= 0)
        {
            return null;
        }
        if (info.Width > MaxSourceDimension || info.Height > MaxSourceDimension
            || (long)info.Width * info.Height > MaxSourcePixels)
        {
            throw new InvalidDataException("Die Auflösung des QR-Bilds ist zu groß.");
        }

        using var source = SKBitmap.Decode(codec);
        if (source is null || source.Width <= 0 || source.Height <= 0)
        {
            return null;
        }

        var scale = Math.Min(1.0, MaxDimension / (double)Math.Max(source.Width, source.Height));
        var width = Math.Max(1, (int)Math.Round(source.Width * scale));
        var height = Math.Max(1, (int)Math.Round(source.Height * scale));

        // Draw onto an opaque white canvas: normalizes the pixel format, scales large photos
        // down and keeps QR codes with transparent background readable.
        using var target = new SKBitmap(new SKImageInfo(width, height, SKColorType.Rgba8888, SKAlphaType.Premul));
        using (var canvas = new SKCanvas(target))
        using (var paint = new SKPaint { FilterQuality = SKFilterQuality.Medium, IsAntialias = true })
        {
            canvas.Clear(SKColors.White);
            canvas.DrawBitmap(source, new SKRect(0, 0, width, height), paint);
        }

        return QrCodeDecoder.FromRgba32(target.GetPixelSpan(), width, height, target.RowBytes, isBgra: false);
    }
}
