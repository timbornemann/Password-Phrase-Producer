using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Vault.Sync;

public sealed class FileSystemVaultSyncProvider : IVaultSyncProvider
{
    public const string ProviderKey = "FileSystem";
    public const string PathParameterKey = "path";

    public string Key => ProviderKey;

    public string DisplayName => "Gemeinsames Laufwerk / Ordner";

    public bool SupportsAutomaticSync => true;

    public Task<bool> IsConfiguredAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        if (configuration.Parameters.TryGetValue(PathParameterKey, out var path) && !string.IsNullOrWhiteSpace(path))
        {
            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    public async Task<VaultSyncRemoteState?> GetRemoteStateAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        var path = GetTargetPath(configuration);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        var info = new FileInfo(path);
        var payload = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        return new VaultSyncRemoteState
        {
            LastModifiedUtc = info.LastWriteTimeUtc,
            ContentLength = payload.LongLength,
            MerkleHash = PasswordVaultService.ComputeMerkleRoot(payload),
            EntityTag = info.LastWriteTimeUtc.ToFileTimeUtc().ToString()
        };
    }

    public async Task<VaultSyncDownloadResult?> DownloadAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        var path = GetTargetPath(configuration);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return null;
        }

        var payload = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        var info = new FileInfo(path);

        return new VaultSyncDownloadResult
        {
            Payload = payload,
            RemoteState = new VaultSyncRemoteState
            {
                LastModifiedUtc = info.LastWriteTimeUtc,
                ContentLength = payload.LongLength,
                MerkleHash = PasswordVaultService.ComputeMerkleRoot(payload),
                EntityTag = info.LastWriteTimeUtc.ToFileTimeUtc().ToString()
            }
        };
    }

    public async Task UploadAsync(VaultSyncUploadRequest request, VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var path = GetTargetPath(configuration);
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException("Es wurde kein Zielpfad für die Dateisynchronisation angegeben.");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        if (File.Exists(path) && request.RemoteStateBeforeUpload is not null)
        {
            var existingPayload = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            var existingHash = PasswordVaultService.ComputeMerkleRoot(existingPayload);
            if (!string.Equals(existingHash, request.RemoteStateBeforeUpload.MerkleHash, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Der entfernte Tresor wurde seit der letzten Prüfung geändert.");
            }
        }

        await File.WriteAllBytesAsync(path, request.Payload, cancellationToken).ConfigureAwait(false);
        File.SetLastWriteTimeUtc(path, request.LocalState.LastModifiedUtc.UtcDateTime);
    }

    private static string? GetTargetPath(VaultSyncConfiguration configuration)
    {
        if (configuration.Parameters.TryGetValue(PathParameterKey, out var path))
        {
            return path?.Trim();
        }

        return null;
    }
}
