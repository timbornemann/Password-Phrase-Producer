using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.ApplicationModel.DataTransfer;
using System.Security.Cryptography;
using System.Text;

namespace Password_Phrase_Producer.Services;

public static class SensitiveClipboard
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(30);
    private static long _generation;

    public static async Task CopyAsync(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        await Gate.WaitAsync().ConfigureAwait(false);
        try
        {
            await Clipboard.Default.SetTextAsync(value).ConfigureAwait(false);
            var generation = ++_generation;
            _ = ClearLaterAsync(ComputeDigest(value), generation);
        }
        finally
        {
            Gate.Release();
        }
    }

    private static async Task ClearLaterAsync(byte[] expectedDigest, long generation)
    {
        await Task.Delay(Lifetime).ConfigureAwait(false);
        await Gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (generation != _generation) return;
            await MainThread.InvokeOnMainThreadAsync(async () =>
            {
                if (Clipboard.Default.HasText &&
                    await Clipboard.Default.GetTextAsync() is { } current)
                {
                    var currentDigest = ComputeDigest(current);
                    try
                    {
                        if (CryptographicOperations.FixedTimeEquals(currentDigest, expectedDigest))
                            await Clipboard.Default.SetTextAsync(null);
                    }
                    finally { CryptographicOperations.ZeroMemory(currentDigest); }
                }
            }).ConfigureAwait(false);
        }
        catch
        {
            // Clipboard access can be revoked or unavailable after the app is backgrounded.
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expectedDigest);
            Gate.Release();
        }
    }

    private static byte[] ComputeDigest(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try { return SHA256.HashData(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
