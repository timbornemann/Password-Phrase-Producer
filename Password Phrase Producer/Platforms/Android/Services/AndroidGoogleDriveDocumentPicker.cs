#if ANDROID
using System;
using System.Threading;
using System.Threading.Tasks;
using global::Android.App;
using global::Android.Content;
using global::Android.OS;
using global::Android.Provider;
using Microsoft.Maui.ApplicationModel;
using Password_Phrase_Producer.Services.Vault.Sync;
using Password_Phrase_Producer;

using AndroidUri = global::Android.Net.Uri;

namespace Password_Phrase_Producer.Platforms.Android.Services;

public sealed class AndroidGoogleDriveDocumentPicker : IGoogleDriveDocumentPicker
{
    private const int CreateDocumentRequestCode = 0x4632;
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    public async Task<string?> CreateDocumentAsync(string suggestedFileName, CancellationToken cancellationToken = default)
    {
        var activity = MainActivity.Current ?? throw new InvalidOperationException("Kein aktives Android-Fenster verfügbar.");
        await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            var tcs = new TaskCompletionSource<string?>();
            EventHandler<ActivityResultEventArgs>? handler = null;

            handler = (_, args) =>
            {
                if (args.RequestCode != CreateDocumentRequestCode)
                {
                    return;
                }

                activity.ActivityResult -= handler;

                if (args.ResultCode == Result.Ok && args.Data?.Data is AndroidUri uri)
                {
                    var takeFlags = args.Data.Flags & (ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission);
                    try
                    {
                        activity.ContentResolver?.TakePersistableUriPermission(uri, takeFlags);
                    }
                    catch (Exception)
                    {
                        // Ignorieren – manche Provider erlauben keine persistente Berechtigung.
                    }

                    tcs.TrySetResult(uri.ToString());
                }
                else
                {
                    tcs.TrySetResult(null);
                }
            };

            using var registration = cancellationToken.Register(() =>
            {
                activity.ActivityResult -= handler;
                tcs.TrySetCanceled(cancellationToken);
            });

            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                activity.ActivityResult += handler;

                var intent = new Intent(Intent.ActionCreateDocument);
                intent.AddCategory(Intent.CategoryOpenable);
                intent.SetType("application/octet-stream");
                var title = string.IsNullOrWhiteSpace(suggestedFileName)
                    ? GoogleDriveVaultSyncProvider.DefaultFileName
                    : suggestedFileName.Trim();
                intent.PutExtra(Intent.ExtraTitle, title);

                activity.StartActivityForResult(intent, CreateDocumentRequestCode);
            }).ConfigureAwait(false);

            return await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    public void ReleasePersistedPermission(string documentUri)
    {
        if (string.IsNullOrWhiteSpace(documentUri))
        {
            return;
        }

        var resolver = (MainActivity.Current ?? Android.App.Application.Context)?.ContentResolver;
        if (resolver is null)
        {
            return;
        }

        var uri = AndroidUri.Parse(documentUri);
        try
        {
            resolver.ReleasePersistableUriPermission(uri, ActivityFlags.GrantReadUriPermission | ActivityFlags.GrantWriteUriPermission);
        }
        catch (Exception)
        {
            // Falls der Provider keine Berechtigungen vergibt, gibt es nichts zu tun.
        }
    }
}
#endif
