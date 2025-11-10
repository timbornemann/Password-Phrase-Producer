using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Vault.Sync;

public interface IVaultSyncProvider
{
    string Key { get; }

    string DisplayName { get; }

    bool SupportsAutomaticSync { get; }

    Task<bool> IsConfiguredAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default);

    Task<VaultSyncRemoteState?> GetRemoteStateAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default);

    Task<VaultSyncDownloadResult?> DownloadAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default);

    Task UploadAsync(VaultSyncUploadRequest request, VaultSyncConfiguration configuration, CancellationToken cancellationToken = default);
}
