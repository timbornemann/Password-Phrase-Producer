using Camera.MAUI;
#if WINDOWS
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Graphics.Imaging;
#elif ANDROID
using Android.Graphics;
#elif IOS || MACCATALYST
using CoreGraphics;
using UIKit;
#endif

namespace Password_Phrase_Producer.Services.Qr;

/// <summary>
/// Frame decoder for Camera.MAUI. Converts the platform frame to grayscale and hands it to
/// <see cref="QrCodeDecoder"/>. Camera.MAUI calls this from a background thread for every
/// n-th preview frame; it must never throw, otherwise the camera stops scanning.
/// </summary>
public sealed class CameraQrDecoder : IBarcodeDecoder
{
    private readonly QrCodeDecoder _decoder = new();

    public void SetDecodeOptions(BarcodeDecodeOptions options)
    {
        // Options are fixed: QR codes only, all strategies handled by QrCodeDecoder.
    }

#if WINDOWS
    public BarcodeResult[] Decode(SoftwareBitmap data) => Decode(() => ToGray(data));

    private static GrayImage? ToGray(SoftwareBitmap bitmap)
    {
        SoftwareBitmap? converted = null;
        try
        {
            if (bitmap.BitmapPixelFormat != BitmapPixelFormat.Gray8)
            {
                converted = SoftwareBitmap.Convert(bitmap, BitmapPixelFormat.Gray8);
                bitmap = converted;
            }

            var width = bitmap.PixelWidth;
            var height = bitmap.PixelHeight;

            int stride;
            int start;
            using (var buffer = bitmap.LockBuffer(BitmapBufferAccessMode.Read))
            {
                var plane = buffer.GetPlaneDescription(0);
                stride = plane.Stride;
                start = plane.StartIndex;
            }

            var raw = new byte[start + stride * height];
            bitmap.CopyToBuffer(raw.AsBuffer());

            if (start == 0 && stride == width)
            {
                return new GrayImage(raw, width, height);
            }

            var pixels = new byte[width * height];
            for (var y = 0; y < height; y++)
            {
                Buffer.BlockCopy(raw, start + y * stride, pixels, y * width, width);
            }

            return new GrayImage(pixels, width, height);
        }
        finally
        {
            converted?.Dispose();
        }
    }
#elif ANDROID
    public BarcodeResult[] Decode(Bitmap data) => Decode(() => ToGray(data));

    private static GrayImage? ToGray(Bitmap bitmap)
    {
        var width = bitmap.Width;
        var height = bitmap.Height;
        var argb = new int[width * height];
        bitmap.GetPixels(argb, 0, width, 0, 0, width, height);

        var gray = new byte[argb.Length];
        for (var i = 0; i < argb.Length; i++)
        {
            var c = argb[i];
            gray[i] = (byte)((((c >> 16) & 0xFF) * 77 + ((c >> 8) & 0xFF) * 150 + (c & 0xFF) * 29) >> 8);
        }

        return new GrayImage(gray, width, height);
    }
#elif IOS || MACCATALYST
    public BarcodeResult[] Decode(UIImage data) => Decode(() => ToGray(data));

    private static GrayImage? ToGray(UIImage image)
    {
        var cgImage = image.CGImage;
        if (cgImage is null)
        {
            return null;
        }

        var width = (int)cgImage.Width;
        var height = (int)cgImage.Height;
        var pixels = new byte[width * height];

        using var colorSpace = CGColorSpace.CreateDeviceGray();
        using var context = new CGBitmapContext(pixels, width, height, 8, width, colorSpace, CGImageAlphaInfo.None);
        context.DrawImage(new CGRect(0, 0, width, height), cgImage);

        return new GrayImage(pixels, width, height);
    }
#else
    public BarcodeResult[] Decode(object data) => Array.Empty<BarcodeResult>();
#endif

    private BarcodeResult[] Decode(Func<GrayImage?> toGray)
    {
        try
        {
            var gray = toGray();
            if (gray is null)
            {
                return Array.Empty<BarcodeResult>();
            }

            return _decoder.DecodeFrame(gray.Value)
                .Select(text => new BarcodeResult(text, Array.Empty<byte>(), Array.Empty<Microsoft.Maui.Graphics.Point>(), Camera.MAUI.BarcodeFormat.QR_CODE))
                .ToArray();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"QR decode failed: {ex.Message}");
            return Array.Empty<BarcodeResult>();
        }
    }
}
