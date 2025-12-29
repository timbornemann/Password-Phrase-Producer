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
    /// Opens the file for writing (overwriting).
    /// </summary>
    Task<Stream> OpenWriteAsync(string path);

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
