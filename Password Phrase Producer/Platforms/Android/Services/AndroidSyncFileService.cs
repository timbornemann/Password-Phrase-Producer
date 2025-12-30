using System;
using System.IO;
using System.Threading.Tasks;
using Android.Content;
using Android.Database;
using Android.Provider;
using Password_Phrase_Producer.Services.Storage;
using Application = Android.App.Application;
using AndroidUri = Android.Net.Uri;

namespace Password_Phrase_Producer.Platforms.Android.Services;

public class AndroidSyncFileService : ISyncFileService
{
    private TaskCompletionSource<string?>? _pickingTcs;

    public async Task<string?> PickAndPersistFileAsync()
    {
        return await LaunchPickerAsync(Intent.ActionOpenDocument);
    }

    public async Task<string?> CreateAndPersistFileAsync(string defaultName)
    {
        return await LaunchPickerAsync(Intent.ActionCreateDocument, defaultName);
    }

    private async Task<string?> LaunchPickerAsync(string action, string? defaultName = null)
    {
        var intent = new Intent(action);
        intent.AddCategory(Intent.CategoryOpenable);
        intent.SetType(action == Intent.ActionCreateDocument ? "application/json" : "*/*"); // Mime type essential for Create
        
        if (defaultName != null)
        {
            intent.PutExtra(Intent.ExtraTitle, defaultName);
        }

        // Essential flags for persistent access
        intent.AddFlags(ActivityFlags.GrantReadUriPermission);
        intent.AddFlags(ActivityFlags.GrantWriteUriPermission);
        intent.AddFlags(ActivityFlags.GrantPersistableUriPermission);

        var currentActivity = Platform.CurrentActivity;
        if (currentActivity == null) return null;
        
        _pickingTcs = new TaskCompletionSource<string?>();

        WebAuthenticatorIntermediateActivity.Callback = (uri) =>
        {
            if (uri != null)
            {
               _pickingTcs.TrySetResult(uri);
            }
            else
            {
                _pickingTcs.TrySetResult(null); // Cancelled
            }
        };

        var pickerIntent = new Intent(currentActivity, typeof(WebAuthenticatorIntermediateActivity));
        pickerIntent.PutExtra("OriginalIntent", intent);
        currentActivity.StartActivity(pickerIntent);

        return await _pickingTcs.Task;
    }

    public Task<Stream> OpenReadAsync(string path)
    {
        var uri = AndroidUri.Parse(path);
        var stream = Application.Context.ContentResolver?.OpenInputStream(uri);
        if (stream == null) throw new FileNotFoundException("Could not open stream for URI", path);
        return Task.FromResult(stream);
    }

    public Task<Stream> OpenWriteAsync(string path)
    {
        var uri = AndroidUri.Parse(path);
        try
        {
            // Use standard OpenOutputStream which is more reliable for Cloud Providers (triggering upload)
            // "wt" = Write + Truncate. 
            // If "wt" acts weirdly with OpenOutputStream on some devices, "w" is usually enough as simple open truncates.
            // But we keep "wt" as it explicitly matches our intent. 
            // Note: Since we use Magic Header protocol, even if truncation fails slightly (garbage at end), 
            // the file is still readable. The priority is ensuring the provider sees the 'write' event.
            var stream = Application.Context.ContentResolver?.OpenOutputStream(uri, "wt");
            if (stream == null) throw new FileNotFoundException("Could not open output stream for URI", path);
            
            return Task.FromResult(stream);
        }
        catch (Exception ex)
        {
             throw new IOException($"Failed to open write stream: {ex.Message}", ex);
        }
    }

    public Task<bool> ExistsAsync(string path)
    {
        try
        {
            var uri = AndroidUri.Parse(path);
            // Try to query it
            using var cursor = Application.Context.ContentResolver?.Query(uri, null, null, null, null);
            return Task.FromResult(cursor != null && cursor.MoveToFirst());
        }
        catch
        {
            return Task.FromResult(false);
        }
    }

    public string GetDisplayName(string path)
    {
        try
        {
             var uri = AndroidUri.Parse(path);
             using var cursor = Application.Context.ContentResolver?.Query(uri, null, null, null, null);
             if (cursor != null && cursor.MoveToFirst())
             {
                 var nameIndex = cursor.GetColumnIndex(OpenableColumns.DisplayName);
                 if (nameIndex >= 0)
                     return cursor.GetString(nameIndex);
             }
        }
        catch { }
        return "Unbekannte Datei";
    }
}
