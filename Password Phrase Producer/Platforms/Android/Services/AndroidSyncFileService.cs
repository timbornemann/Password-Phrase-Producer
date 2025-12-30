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
            var pfd = Application.Context.ContentResolver?.OpenFileDescriptor(uri, "wt");
            if (pfd == null) throw new FileNotFoundException("Could not open PFD for URI", path);
            
            // Detach the FD so we can pass ownership to the FileStream
            var fd = pfd.DetachFd();
            
            // Create a SafeFileHandle that owns the FD (will close it when disposed)
            var safeHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle((nint)fd, ownsHandle: true);
            
            // Use WriteThrough to ensure data hits the disk/storage provider immediately
            // Must use isAsync: false because the handle from OpenFileDescriptor is synchronous.
            var fileStream = new FileStream(safeHandle, FileAccess.Write, 4096, false);
            // FileStream(SafeFileHandle handle, FileAccess access, int bufferSize, bool isAsync)
            // Need overload with FileOptions to verify WriteThrough.
            // FileStream(SafeFileHandle handle, FileAccess access) -> doesn't expose options.
            // We might need to just use Flush(true) on the stream if constructor doesn't allow Options with SafeHandle easily in all .NET versions.
            // Check .NET 8/9 support. 
            // FileStream(SafeFileHandle handle, FileAccess access, int bufferSize)
            // Let's stick to simple constructor but force Flush in a wrapper or return fileStream and hope standard flush is enough? 
            // Previous user error suggested standard write/dispose sequence might have raced.
            
            // Let's configure it simply but perform an explicit Flush(true) before returning? No, we need to flush AFTER writing.
            
            // Since we return 'Stream', we can wrap it.
            var flushingStream = new FlushingStream(fileStream);

            // Explicitly truncate
            fileStream.SetLength(0);
            
            pfd.Dispose(); 
            
            return Task.FromResult<Stream>(flushingStream);
        }
        catch (Exception ex)
        {
             throw new IOException($"Failed to open write stream: {ex.Message}", ex);
        }
    }

    // Helper wrapper to force Flush(true) on dispose
    private class FlushingStream : Stream
    {
        private readonly FileStream _inner;
        public FlushingStream(FileStream inner) { _inner = inner; }
        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => _inner.CanWrite;
        public override long Length => _inner.Length;
        public override long Position { get => _inner.Position; set => _inner.Position = value; }
        public override void Flush() => _inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
        public override void SetLength(long value) => _inner.SetLength(value);
        public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token) => await _inner.WriteAsync(buffer, offset, count, token);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try { _inner.Flush(flushToDisk: true); } catch { }
                _inner.Dispose();
            }
            base.Dispose(disposing);
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
