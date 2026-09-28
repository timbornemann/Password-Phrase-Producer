using ZXing;
using ZXing.Common;
using ZXing.Multi.QrCode;
using ZXing.QrCode;

namespace Password_Phrase_Producer.Services.Qr;

/// <summary>
/// 8-bit grayscale image (one byte per pixel, no row padding).
/// </summary>
public readonly record struct GrayImage(byte[] Pixels, int Width, int Height);

/// <summary>
/// Fast and robust QR code decoding on top of ZXing.
/// Live camera frames get one cheap pass per frame plus a rotating extra strategy, so a
/// frame never blocks for long while dense codes (e.g. Google Authenticator exports with
/// many accounts) are still found within a few frames. Still images try every strategy.
/// </summary>
public sealed class QrCodeDecoder
{
    // Downscaled size for the fast pass. Large enough for dense export codes that fill
    // a reasonable part of the frame, small enough to decode in a few milliseconds.
    private const int FastPassMaxDimension = 1100;
    private const int CropMaxDimension = 1600;
    private const int StillImageMaxDimension = 2400;

    private static readonly IDictionary<DecodeHintType, object> Hints = new Dictionary<DecodeHintType, object>
    {
        [DecodeHintType.POSSIBLE_FORMATS] = new List<BarcodeFormat> { BarcodeFormat.QR_CODE },
        [DecodeHintType.TRY_HARDER] = true,
        [DecodeHintType.CHARACTER_SET] = "UTF-8"
    };

    private int _frameCounter;

    /// <summary>
    /// Decodes a live camera frame. Returns an empty list when no QR code was found.
    /// </summary>
    public IReadOnlyList<string> DecodeFrame(GrayImage frame)
    {
        if (frame.Width <= 0 || frame.Height <= 0)
        {
            return Array.Empty<string>();
        }

        var scaled = Downscale(frame, FastPassMaxDimension);
        var result = DecodeSingle(scaled, useHybrid: true, invert: false);
        if (result is not null)
        {
            return new[] { result };
        }

        // Rotate through the more expensive strategies, one per frame.
        var strategy = Interlocked.Increment(ref _frameCounter) % 4;
        result = strategy switch
        {
            // Global histogram copes better with glare and low contrast screens.
            1 => DecodeSingle(scaled, useHybrid: false, invert: false),
            // Light-on-dark codes (dark mode screens).
            3 => DecodeSingle(scaled, useHybrid: true, invert: true),
            // Every other frame: center crop at full resolution. Acts like a digital zoom for
            // small or very dense codes such as large Google Authenticator exports.
            _ => DecodeSingle(CenterCrop(frame), useHybrid: true, invert: false)
        };

        return result is null ? Array.Empty<string>() : new[] { result };
    }

    /// <summary>
    /// Decodes all QR codes in a still image (screenshot, photo). Tries every strategy until
    /// at least one code was found.
    /// </summary>
    public IReadOnlyList<string> DecodeImage(GrayImage image)
    {
        if (image.Width <= 0 || image.Height <= 0)
        {
            return Array.Empty<string>();
        }

        var candidates = new List<GrayImage>();
        var longest = Math.Max(image.Width, image.Height);
        if (longest <= StillImageMaxDimension)
        {
            candidates.Add(image);
        }

        foreach (var maxDimension in new[] { StillImageMaxDimension, 1600, 1100, 800 })
        {
            if (longest > maxDimension)
            {
                candidates.Add(Downscale(image, maxDimension));
            }
        }

        foreach (var candidate in candidates.DistinctBy(c => (c.Width, c.Height)))
        {
            foreach (var (useHybrid, invert) in new[] { (true, false), (false, false), (true, true), (false, true) })
            {
                var results = DecodeMultiple(candidate, useHybrid, invert);
                if (results.Count > 0)
                {
                    return results;
                }
            }
        }

        return Array.Empty<string>();
    }

    private static string? DecodeSingle(GrayImage image, bool useHybrid, bool invert)
    {
        try
        {
            var result = new QRCodeReader().decode(CreateBitmap(image, useHybrid, invert), Hints);
            return string.IsNullOrEmpty(result?.Text) ? null : result.Text;
        }
        catch (Exception ex) when (ex is ReaderException or ArgumentException or IndexOutOfRangeException)
        {
            return null;
        }
    }

    private static IReadOnlyList<string> DecodeMultiple(GrayImage image, bool useHybrid, bool invert)
    {
        try
        {
            var results = new QRCodeMultiReader().decodeMultiple(CreateBitmap(image, useHybrid, invert), Hints);
            return results?
                .Select(r => r.Text)
                .Where(t => !string.IsNullOrEmpty(t))
                .Distinct(StringComparer.Ordinal)
                .ToList() ?? (IReadOnlyList<string>)Array.Empty<string>();
        }
        catch (Exception ex) when (ex is ReaderException or ArgumentException or IndexOutOfRangeException)
        {
            return Array.Empty<string>();
        }
    }

    private static BinaryBitmap CreateBitmap(GrayImage image, bool useHybrid, bool invert)
    {
        LuminanceSource source = new PlanarYUVLuminanceSource(image.Pixels, image.Width, image.Height, 0, 0, image.Width, image.Height, false);
        if (invert)
        {
            source = new InvertedLuminanceSource(source);
        }

        Binarizer binarizer = useHybrid ? new HybridBinarizer(source) : new GlobalHistogramBinarizer(source);
        return new BinaryBitmap(binarizer);
    }

    /// <summary>
    /// Reduces the image by an integer factor (box filter) so the longest side is at most
    /// <paramref name="maxDimension"/>. Averaging keeps fine QR modules intact far better
    /// than point sampling.
    /// </summary>
    public static GrayImage Downscale(GrayImage image, int maxDimension)
    {
        var longest = Math.Max(image.Width, image.Height);
        if (longest <= maxDimension)
        {
            return image;
        }

        var factor = (longest + maxDimension - 1) / maxDimension;
        var width = image.Width / factor;
        var height = image.Height / factor;
        var pixels = new byte[width * height];
        var area = factor * factor;
        var source = image.Pixels;
        var sums = new int[width];

        for (var y = 0; y < height; y++)
        {
            Array.Clear(sums);
            for (var dy = 0; dy < factor; dy++)
            {
                var rowStart = (y * factor + dy) * image.Width;
                for (var x = 0; x < width; x++)
                {
                    var index = rowStart + x * factor;
                    var sum = 0;
                    for (var dx = 0; dx < factor; dx++)
                    {
                        sum += source[index + dx];
                    }

                    sums[x] += sum;
                }
            }

            var outRow = y * width;
            for (var x = 0; x < width; x++)
            {
                pixels[outRow + x] = (byte)(sums[x] / area);
            }
        }

        return new GrayImage(pixels, width, height);
    }

    /// <summary>
    /// Cuts out the center of the frame at full resolution (at most 60 % of the frame and
    /// <see cref="CropMaxDimension"/> pixels, so very large frames stay cheap).
    /// </summary>
    private static GrayImage CenterCrop(GrayImage image)
    {
        var fraction = Math.Min(0.6, CropMaxDimension / (double)Math.Max(image.Width, image.Height));
        var width = Math.Max(1, (int)(image.Width * fraction));
        var height = Math.Max(1, (int)(image.Height * fraction));
        var left = (image.Width - width) / 2;
        var top = (image.Height - height) / 2;

        var pixels = new byte[width * height];
        for (var y = 0; y < height; y++)
        {
            Buffer.BlockCopy(image.Pixels, (top + y) * image.Width + left, pixels, y * width, width);
        }

        return new GrayImage(pixels, width, height);
    }

    /// <summary>
    /// Converts 32-bit pixels to grayscale (ITU-R BT.601 luma).
    /// </summary>
    public static GrayImage FromRgba32(ReadOnlySpan<byte> pixels, int width, int height, int rowBytes, bool isBgra)
    {
        var gray = new byte[width * height];
        var redOffset = isBgra ? 2 : 0;
        var blueOffset = isBgra ? 0 : 2;

        for (var y = 0; y < height; y++)
        {
            var row = pixels.Slice(y * rowBytes, width * 4);
            var outRow = y * width;
            for (var x = 0; x < width; x++)
            {
                var i = x * 4;
                gray[outRow + x] = (byte)((row[i + redOffset] * 77 + row[i + 1] * 150 + row[i + blueOffset] * 29) >> 8);
            }
        }

        return new GrayImage(gray, width, height);
    }
}
