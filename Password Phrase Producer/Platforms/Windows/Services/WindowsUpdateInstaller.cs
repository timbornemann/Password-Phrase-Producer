using PasswordPhraseProducer.Updates;
using Velopack;
using Velopack.Logging;
using Velopack.Sources;

namespace Password_Phrase_Producer.Platforms.Windows.Services;

public sealed class WindowsUpdateInstaller : IPlatformUpdateInstaller
{
    public bool IsSupported
    {
        get
        {
#if DEBUG
            return false;
#else
            return Velopack.Locators.VelopackLocator.Current.CurrentlyInstalledVersion is not null &&
                   !Velopack.Locators.VelopackLocator.Current.IsPortable;
#endif
        }
    }

    public Task PrepareAsync(UpdateRelease release, string packagePath, CancellationToken cancellationToken) =>
        ReleaseVerifier.VerifyPackageAsync(packagePath, release.Artifact, cancellationToken);

    public async Task<InstallOutcome> InstallAsync(UpdateRelease release, string packagePath, CancellationToken cancellationToken)
    {
        // This source exposes only the explicitly selected, signed and verified full package.
        // No live feed is consulted between the user's click and applying the update.
        var manager = new UpdateManager(new VerifiedPackageSource(release, packagePath));
        var update = await manager.CheckForUpdatesAsync();
        if (update is null) throw new InvalidOperationException("Das Update ist nicht mehr anwendbar.");
        await manager.DownloadUpdatesAsync(update, cancelToken: cancellationToken);
        await ReleaseVerifier.VerifyPackageAsync(Path.Combine(Velopack.Locators.VelopackLocator.Current.PackagesDir!,
            release.Artifact.FileName), release.Artifact, cancellationToken);
        manager.ApplyUpdatesAndRestart(update.TargetFullRelease);
        return InstallOutcome.Installed;
    }

    private sealed class VerifiedPackageSource(UpdateRelease release, string path) : IUpdateSource
    {
        private VelopackAsset Asset => new()
        {
            PackageId = UpdateIdentity.WindowsPackageId,
            Version = Velopack.SemanticVersion.Parse(release.Version),
            Type = VelopackAssetType.Full,
            FileName = release.Artifact.FileName,
            SHA256 = release.Artifact.Sha256,
            Size = release.Artifact.Size,
            NotesMarkdown = release.Signed.Manifest.Notes
        };

        public Task<VelopackAssetFeed> GetReleaseFeed(IVelopackLogger logger, string? appId, string channel,
            Guid? stagingId = null, VelopackAsset? latestLocalRelease = null) =>
            Task.FromResult(new VelopackAssetFeed { Assets = [Asset] });

        public async Task DownloadReleaseEntry(IVelopackLogger logger, VelopackAsset releaseEntry, string localFile,
            Action<int> progress, CancellationToken cancelToken = default)
        {
            if (releaseEntry.FileName != release.Artifact.FileName || releaseEntry.SHA256 != release.Artifact.Sha256)
                throw new InvalidDataException("Das Updatepaket wurde nicht freigegeben.");
            await ReleaseVerifier.VerifyPackageAsync(path, release.Artifact, cancelToken);
            await using var source = File.OpenRead(path);
            await using (var target = new FileStream(localFile, FileMode.Create, FileAccess.Write, FileShare.None))
                await source.CopyToAsync(target, cancelToken);
            await ReleaseVerifier.VerifyPackageAsync(localFile, release.Artifact, cancelToken);
            progress(100);
        }
    }
}
