using System.Text.Json.Serialization;

namespace PasswordPhraseProducer.Updates;

public static class UpdateIdentity
{
    public const string Repository = "timbornemann/Password-Phrase-Producer";
    public const string WindowsPackageId = "Timbornemann.PasswordPhraseProducer";
    public const string AndroidPackageId = "com.companyname.passwordphraseproducer";
    public const string ManifestName = "update-manifest.json";
    public const string SignatureName = "update-manifest.sig";
    public static readonly TimeSpan CheckInterval = TimeSpan.FromHours(6);
}

public sealed record UpdateManifest
{
    public int SchemaVersion { get; init; } = 1;
    public required string Version { get; init; }
    public required long BuildNumber { get; init; }
    public required string ReleaseTag { get; init; }
    public string Notes { get; init; } = "";
    public required UpdateArtifact[] Artifacts { get; init; }
}

public sealed record UpdateArtifact
{
    public required string Platform { get; init; }
    public required string Architecture { get; init; }
    public required string Kind { get; init; }
    public required string FileName { get; init; }
    public required long Size { get; init; }
    public required string Sha256 { get; init; }
}

public sealed record SignedRelease(UpdateManifest Manifest, byte[] ManifestBytes, byte[] Signature);
public sealed record UpdateRelease(SignedRelease Signed, UpdateArtifact Artifact)
{
    public string Version => Signed.Manifest.Version;
    public long BuildNumber => Signed.Manifest.BuildNumber;
    public Uri DownloadUri => ReleaseVerifier.AssetUri(Signed.Manifest.ReleaseTag, Artifact.FileName);
}

public sealed record InstalledApplication(string Version, long BuildNumber, string Platform, string Architecture);
public enum UpdatePhase { Idle, Checking, Current, Available, Downloading, Ready, Preparing, Installing, Error, Unsupported }
public sealed record UpdateState(UpdatePhase Phase, UpdateRelease? Release = null, double Progress = 0, string? Message = null);
public enum InstallOutcome { Installed, Cancelled }

public interface IAppUpdateService
{
    UpdateState State { get; }
    event EventHandler? StateChanged;
    Task InitializeAsync(CancellationToken cancellationToken = default);
    Task CheckAsync(bool manual = false, CancellationToken cancellationToken = default);
    Task DownloadAsync(bool manual = true, CancellationToken cancellationToken = default);
    Task InstallAsync(CancellationToken cancellationToken = default);
    void CancelDownload();
}

public interface IUpdateSettings
{
    bool AutomaticChecks { get; set; }
    bool AutomaticDownloads { get; set; }
    DateTimeOffset? LastCheckUtc { get; set; }
}

public interface IUpdateNetworkPolicy
{
    bool HasInternet { get; }
    bool IsUnmetered { get; }
    event EventHandler? Changed;
}

public interface IUpdateFeed
{
    Task<SignedRelease?> GetLatestAsync(CancellationToken cancellationToken);
}

public interface IPlatformUpdateInstaller
{
    bool IsSupported { get; }
    Task PrepareAsync(UpdateRelease release, string packagePath, CancellationToken cancellationToken);
    Task<InstallOutcome> InstallAsync(UpdateRelease release, string packagePath, CancellationToken cancellationToken);
}

public interface IStorageSpace
{
    long AvailableBytes(string directory);
}
