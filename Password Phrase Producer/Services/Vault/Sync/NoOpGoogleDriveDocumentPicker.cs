using System;
using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Vault.Sync;

public sealed class NoOpGoogleDriveDocumentPicker : IGoogleDriveDocumentPicker
{
    public Task<string?> CreateDocumentAsync(string suggestedFileName, CancellationToken cancellationToken = default)
        => Task.FromException<string?>(new PlatformNotSupportedException("Die Dateiauswahl für Google Drive wird nur unter Android unterstützt."));

    public void ReleasePersistedPermission(string documentUri)
    {
        // Nicht erforderlich auf nicht unterstützten Plattformen.
    }
}
