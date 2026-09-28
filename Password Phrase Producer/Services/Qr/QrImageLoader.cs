using SkiaSharp;

namespace Password_Phrase_Producer.Services.Qr;

/// <summary>
/// Loads screenshots or photos as grayscale images for <see cref="QrCodeDecoder"/>.
/// </summary>
public static class QrImageLoader
{
    private const int MaxDimension = 3000;

    public static GrayImage? Load(Stream stream)
    {
        using var source = SKBitmap.Decode(stream);
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
