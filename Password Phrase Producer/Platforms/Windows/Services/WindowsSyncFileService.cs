using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.Services.Storage;

namespace Password_Phrase_Producer.Platforms.Windows.Services;

public class WindowsSyncFileService : ISyncFileService
{
    public async Task<string?> PickAndPersistFileAsync()
    {
        try
        {
            var result = await FilePicker.Default.PickAsync(new PickOptions
            {
                PickerTitle = "Synchronisations-Datei auswählen",
                FileTypes = new FilePickerFileType(new Dictionary<DevicePlatform, IEnumerable<string>>
                {
                    { DevicePlatform.WinUI, new[] { ".vault", ".json" } }
                })
            });

            return result?.FullPath;
        }
        catch
        {
            return null;
        }
    }

    public async Task<string?> CreateAndPersistFileAsync(string defaultName)
    {
        try
        {
            using var stream = new MemoryStream();
            var result = await CommunityToolkit.Maui.Storage.FileSaver.Default.SaveAsync(defaultName, stream, System.Threading.CancellationToken.None);
            if (result.IsSuccessful)
            {
                return result.FilePath;
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    public Task<Stream> OpenReadAsync(string path)
    {
        return Task.FromResult<Stream>(File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
    }

    public Task<Stream> OpenWriteAsync(string path)
    {
        return Task.FromResult<Stream>(File.Open(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite));
    }

    public Task<bool> ExistsAsync(string path)
    {
        return Task.FromResult(File.Exists(path));
    }

    public string GetDisplayName(string path)
    {
        return Path.GetFileName(path);
    }
}
