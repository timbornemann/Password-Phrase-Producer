namespace PasswordPhraseProducer.Updates;

public sealed class UpdateDownloader(HttpClient http, UpdatePackageCache cache, IStorageSpace storage)
{
    public async Task DownloadAsync(UpdateRelease release, Action<double> progress, CancellationToken cancellationToken)
    {
        var path = cache.PackagePath(release);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        // Allow space for the downloaded archive and unpacked/replaced program files.
        if (storage.AvailableBytes(Path.GetDirectoryName(path)!) < checked(release.Artifact.Size * 3 + 64L * 1024 * 1024))
            throw new IOException("Nicht genügend freier Speicher für das Update.");
        var partialPath = path + ".partial";
        try
        {
            using var response = await http.GetAsync(release.DownloadUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is { } length && length != release.Artifact.Size)
                throw new InvalidDataException("Die Downloadgröße stimmt nicht mit dem Manifest überein.");
            await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using (var output = new FileStream(partialPath, FileMode.Create, FileAccess.Write, FileShare.None,
                81920, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                var buffer = new byte[81920];
                long total = 0;
                int count;
                while ((count = await input.ReadAsync(buffer, cancellationToken).AsTask()
                           .WaitAsync(TimeSpan.FromSeconds(45), cancellationToken)) > 0)
                {
                    total += count;
                    if (total > release.Artifact.Size) throw new InvalidDataException("Die Update-Datei ist zu groß.");
                    await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken);
                    progress((double)total / release.Artifact.Size);
                }
                await output.FlushAsync(cancellationToken);
                output.Flush(true);
            }
            await ReleaseVerifier.VerifyPackageAsync(partialPath, release.Artifact, cancellationToken);
            await cache.StoreMetadataAsync(release, cancellationToken);
            File.Move(partialPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(partialPath)) File.Delete(partialPath);
        }
    }
}
