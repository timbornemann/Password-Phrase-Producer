using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Vault.Sync;

public interface IGoogleDriveDocumentPicker
{
    Task<string?> CreateDocumentAsync(string suggestedFileName, CancellationToken cancellationToken = default);

    Task<string?> PickExistingDocumentAsync(CancellationToken cancellationToken = default);

    void ReleasePersistedPermission(string documentUri);
}
