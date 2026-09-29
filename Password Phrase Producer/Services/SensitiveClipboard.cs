using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.ApplicationModel.DataTransfer;

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
            _ = ClearLaterAsync(value, generation);
        }
        finally
        {
            Gate.Release();
        }
    }

    private static async Task ClearLaterAsync(string value, long generation)
    {
        await Task.Delay(Lifetime).ConfigureAwait(false);
        await Gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (generation != _generation) return;
            await MainThread.InvokeOnMainThreadAsync(async () =>
            {
                if (Clipboard.Default.HasText &&
                    string.Equals(await Clipboard.Default.GetTextAsync(), value, StringComparison.Ordinal))
                    await Clipboard.Default.SetTextAsync(null);
            }).ConfigureAwait(false);
        }
        catch
        {
            // Clipboard access can be revoked or unavailable after the app is backgrounded.
        }
        finally
        {
            Gate.Release();
        }
    }
}
