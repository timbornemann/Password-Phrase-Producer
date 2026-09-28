namespace PasswordPhraseProducer.Updates;

public sealed class UpdatePackageCache(string root, ReleaseVerifier verifier)
{
    public string Root { get; } = Path.GetFullPath(root);
    private string InstallationMarker => Path.Combine(Root, "installation-attempt");

    public string DirectoryFor(UpdateRelease release) => Path.Combine(Root, $"release-{release.Version}-{release.BuildNumber}");
    public string PackagePath(UpdateRelease release) => Path.Combine(DirectoryFor(release), release.Artifact.FileName);

    public Task RecordInstallationAttemptAsync(UpdateRelease release, CancellationToken ct) =>
        AtomicFile.WriteAsync(InstallationMarker, System.Text.Encoding.UTF8.GetBytes(Path.GetFileName(DirectoryFor(release))), ct);

    public async Task<SignedRelease?> ReadInstallationAttemptAsync(CancellationToken ct)
    {
        try
        {
            if (!File.Exists(InstallationMarker) || new FileInfo(InstallationMarker).Length > 256) return null;
            var name = await File.ReadAllTextAsync(InstallationMarker, ct);
            if (!name.StartsWith("release-", StringComparison.Ordinal) || name.Any(c => !char.IsAsciiDigit(c) && c != '.' && c != '-' && !char.IsAsciiLetter(c)))
                return null;
            var directory = Path.Combine(Root, name);
            var manifestPath = Path.Combine(directory, UpdateIdentity.ManifestName);
            var signaturePath = Path.Combine(directory, UpdateIdentity.SignatureName);
            if (new FileInfo(manifestPath).Length > ReleaseVerifier.MaxManifestBytes || new FileInfo(signaturePath).Length != 64)
                return null;
            var signed = verifier.Verify(await File.ReadAllBytesAsync(manifestPath, ct), await File.ReadAllBytesAsync(signaturePath, ct));
            return name == $"release-{signed.Manifest.Version}-{signed.Manifest.BuildNumber}" ? signed : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or ArgumentException)
        { return null; }
    }

    public void ClearInstallationAttempt()
    {
        try { File.Delete(InstallationMarker); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    public async Task StoreMetadataAsync(UpdateRelease release, CancellationToken ct)
    {
        var directory = DirectoryFor(release);
        Directory.CreateDirectory(directory);
        await AtomicFile.WriteAsync(Path.Combine(directory, UpdateIdentity.ManifestName), release.Signed.ManifestBytes, ct);
        await AtomicFile.WriteAsync(Path.Combine(directory, UpdateIdentity.SignatureName), release.Signed.Signature, ct);
    }

    public async Task<UpdateRelease?> FindReadyAsync(InstalledApplication installed, CancellationToken ct)
    {
        if (!Directory.Exists(Root)) return null;
        UpdateRelease? best = null;
        foreach (var directory in Directory.EnumerateDirectories(Root, "release-*"))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var manifestPath = Path.Combine(directory, UpdateIdentity.ManifestName);
                var signaturePath = Path.Combine(directory, UpdateIdentity.SignatureName);
                if (new FileInfo(manifestPath).Length > ReleaseVerifier.MaxManifestBytes || new FileInfo(signaturePath).Length != 64)
                    continue;
                var signed = verifier.Verify(await File.ReadAllBytesAsync(manifestPath, ct), await File.ReadAllBytesAsync(signaturePath, ct));
                var release = ReleaseVerifier.Select(signed, installed);
                if (release is null || !string.Equals(Path.GetFullPath(directory), DirectoryFor(release), StringComparison.OrdinalIgnoreCase))
                    continue;
                await ReleaseVerifier.VerifyPackageAsync(PackagePath(release), release.Artifact, ct);
                if (best is null || release.BuildNumber > best.BuildNumber) best = release;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or ArgumentException)
            {
                // Incomplete or tampered cache entries never become installable.
            }
        }
        return best;
    }
}

public sealed class DiskStorageSpace : IStorageSpace
{
    public long AvailableBytes(string directory) => new DriveInfo(Path.GetPathRoot(Path.GetFullPath(directory))!).AvailableFreeSpace;
}
