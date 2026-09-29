using System.IO;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Storage;

public interface ISyncFileService
{
    /// <summary>
    /// Opens a system file picker to select a file.
    /// On Android, this requests persistent permission.
    /// Returns the "path" (or URI string) to the selected file, or null if cancelled.
    /// </summary>
    Task<string?> PickAndPersistFileAsync();
    
    /// <summary>
    /// Opens the file for reading.
    /// </summary>
    Task<Stream> OpenReadAsync(string path);

    /// <summary>
    /// Replaces the sync file with complete contents. Implementations should
    /// publish atomically when the storage provider supports it.
    /// </summary>
    Task WriteAllBytesAsync(string path, byte[] contents, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new file (via system picker) and requests persistent permission.
    /// Returns the path/URI.
    /// </summary>
    Task<string?> CreateAndPersistFileAsync(string defaultName);
    
    /// <summary>
    /// Checks if the file exists (or is accessible).
    /// </summary>
    Task<bool> ExistsAsync(string path);

    /// <summary>
    /// Gets a user-friendly name for the file (e.g. filename).
    /// </summary>
    string GetDisplayName(string path);
}
