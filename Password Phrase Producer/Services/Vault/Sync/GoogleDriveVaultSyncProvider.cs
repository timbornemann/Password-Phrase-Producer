using System;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

#if ANDROID
using AndroidContentResolver = global::Android.Content.ContentResolver;
using AndroidDocumentsContract = global::Android.Provider.DocumentsContract;
using AndroidUri = global::Android.Net.Uri;
using AndroidParcelFileDescriptor = global::Android.OS.ParcelFileDescriptor;
#endif

namespace Password_Phrase_Producer.Services.Vault.Sync;

public sealed class GoogleDriveVaultSyncProvider : IVaultSyncProvider
{
    public const string ProviderKey = "GoogleDrive";
    public const string DocumentUriParameterKey = "documentUri";
    public const string DefaultFileName = "vault.json.enc";

    public string Key => ProviderKey;

    public string DisplayName => "Google Drive";

    public bool SupportsAutomaticSync => true;

    public Task<bool> IsConfiguredAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
        => Task.FromResult(GetDocumentUri(configuration) is not null);

    public async Task<VaultSyncRemoteState?> GetRemoteStateAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
#if ANDROID
        var documentUri = GetDocumentUri(configuration);
        if (documentUri is null)
        {
            return null;
        }

        var snapshot = await TryReadDocumentAsync(documentUri, cancellationToken).ConfigureAwait(false);
        return snapshot is null ? null : CreateRemoteState(snapshot);
#else
        throw new PlatformNotSupportedException("Die Google-Drive-Synchronisation wird nur unter Android unterstützt.");
#endif
    }

    public async Task<VaultSyncDownloadResult?> DownloadAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
#if ANDROID
        var documentUri = GetDocumentUri(configuration);
        if (documentUri is null)
        {
            return null;
        }

        var snapshot = await TryReadDocumentAsync(documentUri, cancellationToken).ConfigureAwait(false);
        if (snapshot is null)
        {
            return null;
        }

        return new VaultSyncDownloadResult
        {
            Payload = snapshot.Payload,
            RemoteState = CreateRemoteState(snapshot)
        };
#else
        throw new PlatformNotSupportedException("Die Google-Drive-Synchronisation wird nur unter Android unterstützt.");
#endif
    }

    public async Task UploadAsync(VaultSyncUploadRequest request, VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

#if ANDROID
        var documentUri = GetDocumentUri(configuration);
        if (documentUri is null)
        {
            throw new InvalidOperationException("Es wurde keine Google-Drive-Datei für die Synchronisation ausgewählt.");
        }

        if (request.RemoteStateBeforeUpload is not null)
        {
            var existingSnapshot = await TryReadDocumentAsync(documentUri, cancellationToken).ConfigureAwait(false);
            if (existingSnapshot is not null)
            {
                var existingHash = PasswordVaultService.ComputeMerkleRoot(existingSnapshot.Payload);
                if (!string.Equals(existingHash, request.RemoteStateBeforeUpload.MerkleHash, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("Der entfernte Tresor wurde seit der letzten Synchronisation verändert.");
                }
            }
        }

        await WriteDocumentAsync(documentUri, request.Payload, cancellationToken).ConfigureAwait(false);
#else
        throw new PlatformNotSupportedException("Die Google-Drive-Synchronisation wird nur unter Android unterstützt.");
#endif
    }

    private static VaultSyncRemoteState CreateRemoteState(DocumentSnapshot snapshot)
        => new()
        {
            LastModifiedUtc = snapshot.LastModifiedUtc,
            MerkleHash = PasswordVaultService.ComputeMerkleRoot(snapshot.Payload),
            ContentLength = snapshot.ContentLength,
            EntityTag = snapshot.LastModifiedUtc.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture)
        };

    private static string? GetDocumentUri(VaultSyncConfiguration configuration)
    {
        if (configuration.Parameters.TryGetValue(DocumentUriParameterKey, out var value) && !string.IsNullOrWhiteSpace(value))
        {
            return value.Trim();
        }

        return null;
    }

#if ANDROID
    private static async Task<DocumentSnapshot?> TryReadDocumentAsync(string documentUri, CancellationToken cancellationToken)
    {
        var context = global::Android.App.Application.Context;
        var resolver = context?.ContentResolver;
        if (resolver is null)
        {
            return null;
        }

        var uri = AndroidUri.Parse(documentUri);
        try
        {
            await using var stream = OpenInputStream(resolver, uri);
            if (stream is null)
            {
                return null;
            }

            using var buffer = new MemoryStream();
            await stream.CopyToAsync(buffer, 81920, cancellationToken).ConfigureAwait(false);
            var payload = buffer.ToArray();

            var metadata = QueryDocumentMetadata(resolver, uri);
            var lastModified = metadata.LastModifiedUtc ?? DateTimeOffset.UtcNow;
            var length = metadata.Size ?? payload.LongLength;

            return new DocumentSnapshot(payload, lastModified, length);
        }
        catch (Java.IO.FileNotFoundException)
        {
            return null;
        }
    }

    private static async Task WriteDocumentAsync(string documentUri, byte[] payload, CancellationToken cancellationToken)
    {
        var context = global::Android.App.Application.Context;
        var resolver = context?.ContentResolver;
        if (resolver is null)
        {
            throw new InvalidOperationException("Die Google-Drive-Datei konnte nicht geöffnet werden.");
        }

        var uri = AndroidUri.Parse(documentUri);
        try
        {
            await using var stream = OpenOutputStream(resolver, uri);
            await stream.WriteAsync(payload.AsMemory(), cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Java.IO.FileNotFoundException ex)
        {
            throw new InvalidOperationException("Die Google-Drive-Datei konnte nicht geöffnet werden.", ex);
        }
    }

    private static Stream? OpenInputStream(AndroidContentResolver resolver, AndroidUri uri)
    {
        var stream = resolver.OpenInputStream(uri);
        if (stream is not null)
        {
            return stream;
        }

        var descriptor = resolver.OpenFileDescriptor(uri, "r");
        if (descriptor is null)
        {
            return null;
        }

        var javaStream = new AndroidParcelFileDescriptor.AutoCloseInputStream(descriptor);
        return new global::Android.Runtime.InputStreamInvoker(javaStream);
    }

    private static Stream OpenOutputStream(AndroidContentResolver resolver, AndroidUri uri)
    {
        var stream = resolver.OpenOutputStream(uri, "wt");
        if (stream is not null)
        {
            return stream;
        }

        var descriptor = resolver.OpenFileDescriptor(uri, "w");
        if (descriptor is null)
        {
            throw new InvalidOperationException("Die Google-Drive-Datei konnte nicht geschrieben werden.");
        }

        var javaStream = new AndroidParcelFileDescriptor.AutoCloseOutputStream(descriptor);
        return new global::Android.Runtime.OutputStreamInvoker(javaStream);
    }

    private static DocumentMetadata QueryDocumentMetadata(AndroidContentResolver resolver, AndroidUri uri)
    {
        var projection = new[]
        {
            AndroidDocumentsContract.Document.ColumnLastModified,
            AndroidDocumentsContract.Document.ColumnSize
        };

        using var cursor = resolver.Query(uri, projection, null, null, null);
        if (cursor is null || !cursor.MoveToFirst())
        {
            return new DocumentMetadata(null, null);
        }

        DateTimeOffset? lastModified = null;
        long? size = null;

        var lastModifiedIndex = cursor.GetColumnIndex(AndroidDocumentsContract.Document.ColumnLastModified);
        if (lastModifiedIndex >= 0 && !cursor.IsNull(lastModifiedIndex))
        {
            var value = cursor.GetLong(lastModifiedIndex);
            if (value > 0)
            {
                lastModified = DateTimeOffset.FromUnixTimeMilliseconds(value);
            }
        }

        var sizeIndex = cursor.GetColumnIndex(AndroidDocumentsContract.Document.ColumnSize);
        if (sizeIndex >= 0 && !cursor.IsNull(sizeIndex))
        {
            var value = cursor.GetLong(sizeIndex);
            if (value >= 0)
            {
                size = value;
            }
        }

        return new DocumentMetadata(lastModified, size);
    }
#endif

    private sealed record DocumentSnapshot(byte[] Payload, DateTimeOffset LastModifiedUtc, long ContentLength);

#if ANDROID
    private sealed record DocumentMetadata(DateTimeOffset? LastModifiedUtc, long? Size);
#endif
}
