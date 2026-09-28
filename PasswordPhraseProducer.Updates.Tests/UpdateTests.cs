using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed partial class UpdateTests
{
    [Fact]
    public void ManifestRequiresTrustedSignatureAndCompleteArtifacts()
    {
        using var f = new Fixture();
        Assert.Equal("2.5.9", f.Verifier.Verify(f.Signed.ManifestBytes, f.Signed.Signature).Manifest.Version);
        var tampered = f.Signed.ManifestBytes.ToArray();
        tampered[20] ^= 1;
        Assert.Throws<CryptographicException>(() => f.Verifier.Verify(tampered, f.Signed.Signature));
        using var foreign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Assert.Throws<CryptographicException>(() => f.Verifier.Verify(f.Signed.ManifestBytes,
            foreign.SignData(f.Signed.ManifestBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        Assert.Throws<InvalidDataException>(() => f.Sign(f.Signed.Manifest with { Artifacts = [] }));
    }

    [Theory]
    [InlineData("../evil.apk")]
    [InlineData("C:\\evil.apk")]
    [InlineData("https://evil.test/update.apk")]
    public void RejectsUnsafeArtifactNames(string name)
    {
        using var f = new Fixture();
        var artifacts = f.Signed.Manifest.Artifacts.ToArray();
        artifacts[2] = artifacts[2] with { FileName = name };
        Assert.Throws<InvalidDataException>(() => f.Sign(f.Signed.Manifest with { Artifacts = artifacts }));
    }

    [Theory]
    [InlineData("2.5.9", 159, false)]
    [InlineData("2.5.8", 158, true)]
    [InlineData("2.5.10", 160, false)]
    [InlineData("2.4.0", 999, false)]
    [InlineData("1.0.0", 1, true)]
    public void ComparesVersionsNumericallyAndRejectsEqualBuildsAndDowngrades(string installed, long build, bool expected)
    {
        using var f = new Fixture();
        Assert.Equal(expected, ReleaseVerifier.Select(f.Signed, new(installed, build, "android", "universal")) is not null);
        Assert.Null(ReleaseVerifier.Select(f.Signed, new("1.0.0", 1, "windows", "arm64")));
    }

    [Fact]
    public async Task AutomaticDownloadNeverInstallsAndSurvivesRestart()
    {
        using var f = new Fixture();
        await f.Service.CheckAsync();
        Assert.Equal(UpdatePhase.Ready, f.Service.State.Phase);
        Assert.Equal(0, f.Installer.Calls);
        var restarted = f.CreateService();
        await restarted.InitializeAsync();
        Assert.Equal(UpdatePhase.Ready, restarted.State.Phase);
        Assert.Equal(0, f.Installer.Calls);
        f.Network.Online = false;
        await restarted.InstallAsync();
        Assert.Equal(1, f.Installer.Calls); // A verified cached update also works offline.
    }

    [Fact]
    public async Task InstallationSuccessIsConfirmedByTheVersionOfTheRestartedApp()
    {
        using var f = new Fixture();
        await f.Service.CheckAsync();
        await f.Service.InstallAsync();
        var restarted = f.CreateService(f.Installed with { Version = "2.5.9", BuildNumber = 159 });
        await restarted.InitializeAsync();
        Assert.Equal(UpdatePhase.Current, restarted.State.Phase);
        Assert.Contains("erfolgreich installiert", restarted.State.Message);
        await restarted.CheckAsync(manual: true);
        Assert.Contains("erfolgreich installiert", restarted.State.Message);
    }

    [Fact]
    public async Task InterruptedInstallationRemainsAnExplicitRetryAndNeverReportsSuccess()
    {
        using var f = new Fixture();
        await f.Service.CheckAsync();
        await f.Service.InstallAsync();
        var restarted = f.CreateService(); // The old version is still running after an interrupted install.
        await restarted.InitializeAsync();
        Assert.Equal(UpdatePhase.Ready, restarted.State.Phase);
        Assert.Contains("nicht abgeschlossen", restarted.State.Message);
        Assert.Equal(1, f.Installer.Calls);
    }

    [Fact]
    public async Task MeteredNetworkRequiresExplicitDownload()
    {
        using var f = new Fixture();
        f.Network.Unmetered = false;
        await f.Service.CheckAsync();
        Assert.Equal(UpdatePhase.Available, f.Service.State.Phase);
        Assert.Equal(0, f.Handler.Calls);
        await f.Service.DownloadAsync();
        Assert.Equal(UpdatePhase.Ready, f.Service.State.Phase);
    }

    [Fact]
    public async Task WaitingDownloadStartsOnUnmeteredNetworkWithoutWaitingSixHours()
    {
        using var f = new Fixture();
        f.Network.Unmetered = false;
        await f.Service.CheckAsync();
        f.Network.Unmetered = true;
        await f.Service.CheckAsync();
        Assert.Equal(1, f.Feed.Calls);
        Assert.Equal(UpdatePhase.Ready, f.Service.State.Phase);
    }

    [Fact]
    public async Task GitHubFeedUsesVerifiedTagAndIgnoresUntrustedAssetUrls()
    {
        using var f = new Fixture();
        var json = JsonSerializer.SerializeToUtf8Bytes(new[] { new
        {
            draft = false, prerelease = false, tag_name = "v2.5.9",
            assets = f.Signed.Manifest.Artifacts.Select(a => new { name = a.FileName, size = a.Size, state = "uploaded", browser_download_url = "https://untrusted.invalid/evil" })
                .Concat(new[] {
                    new { name = UpdateIdentity.ManifestName, size = (long)f.Signed.ManifestBytes.Length, state = "uploaded", browser_download_url = "https://untrusted.invalid/evil" },
                    new { name = UpdateIdentity.SignatureName, size = 64L, state = "uploaded", browser_download_url = "https://untrusted.invalid/evil" } }).ToArray()
        } });
        using var http = new HttpClient(new RoutingHandler(uri =>
        {
            Assert.Contains(UpdateIdentity.Repository, uri.AbsolutePath);
            if (uri.Host == "api.github.com") return json;
            Assert.Equal("github.com", uri.Host);
            Assert.Contains("/releases/download/v2.5.9/", uri.AbsolutePath);
            return uri.AbsolutePath.EndsWith(".sig") ? f.Signed.Signature : f.Signed.ManifestBytes;
        }));
        var result = await new GitHubUpdateFeed(http, f.Verifier).GetLatestAsync(default);
        Assert.Equal("2.5.9", result!.Manifest.Version);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task GitHubFeedIgnoresDraftAndPrerelease(bool draft, bool prerelease)
    {
        using var f = new Fixture();
        using var http = new HttpClient(new RoutingHandler(_ => JsonSerializer.SerializeToUtf8Bytes(new[] { new { draft, prerelease } })));
        Assert.Null(await new GitHubUpdateFeed(http, f.Verifier).GetLatestAsync(default));
    }

    [Fact]
    public async Task ChecksAreThrottledButManualCheckBypassesInterval()
    {
        using var f = new Fixture();
        f.Settings.AutomaticDownloads = false;
        await f.Service.CheckAsync();
        await f.Service.CheckAsync();
        Assert.Equal(1, f.Feed.Calls);
        f.Clock.Now += TimeSpan.FromHours(6);
        await f.Service.CheckAsync();
        await f.Service.CheckAsync(manual: true);
        Assert.Equal(3, f.Feed.Calls);
        f.Settings.AutomaticChecks = false;
        f.Clock.Now += TimeSpan.FromDays(1);
        await f.Service.CheckAsync();
        Assert.Equal(3, f.Feed.Calls);
    }

    [Fact]
    public async Task ConcurrentChecksUseOneRequest()
    {
        using var f = new Fixture();
        f.Feed.Block = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = f.Service.CheckAsync(true);
        await f.Service.CheckAsync(true);
        Assert.Equal(1, f.Feed.Calls);
        f.Feed.Block.SetResult();
        await first;
    }

    [Fact]
    public async Task RevalidatesPackageImmediatelyBeforeInstalling()
    {
        using var f = new Fixture();
        await f.Service.CheckAsync();
        var path = f.Cache.PackagePath(f.Service.State.Release!);
        var content = File.ReadAllBytes(path);
        content[0] ^= 1;
        File.WriteAllBytes(path, content);
        await f.Service.InstallAsync();
        Assert.Equal(0, f.Installer.Calls);
        Assert.Equal(UpdatePhase.Error, f.Service.State.Phase);
        Assert.Null(await f.Cache.FindReadyAsync(f.Installed, default));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CorruptOrTruncatedDownloadCannotBecomeReady(bool truncate)
    {
        using var f = new Fixture();
        f.Handler.Data = truncate ? [1] : Enumerable.Repeat((byte)5, f.Bytes.Length).ToArray();
        await f.Service.CheckAsync();
        Assert.Equal(UpdatePhase.Error, f.Service.State.Phase);
        Assert.Null(await f.Cache.FindReadyAsync(f.Installed, default));
        Assert.Empty(Directory.GetFiles(f.Root, "*.partial", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task NoSpaceStopsBeforeDownloading()
    {
        using var f = new Fixture();
        f.Storage.Bytes = 1;
        await f.Service.CheckAsync();
        Assert.Equal(UpdatePhase.Error, f.Service.State.Phase);
        Assert.Equal(0, f.Handler.Calls);
    }

    [Fact]
    public async Task MeteredNetworkChangeCancelsAutomaticDownload()
    {
        using var f = new Fixture();
        f.Handler.OnRequest = () => { f.Network.Unmetered = false; f.Network.Notify(); };
        await f.Service.CheckAsync();
        Assert.Equal(UpdatePhase.Available, f.Service.State.Phase);
        Assert.Null(await f.Cache.FindReadyAsync(f.Installed, default));
    }

    [Fact]
    public async Task OfflineAndFailedChecksPreserveReadyPackage()
    {
        using var f = new Fixture();
        await f.Service.CheckAsync();
        f.Feed.Error = new HttpRequestException();
        await f.Service.CheckAsync(true);
        Assert.Equal(UpdatePhase.Ready, f.Service.State.Phase);
        f.Network.Online = false;
        await f.Service.CheckAsync(true);
        Assert.Equal(UpdatePhase.Ready, f.Service.State.Phase);
    }

    [Fact]
    public async Task CancellingInstallationAllowsRetry()
    {
        using var f = new Fixture();
        f.Installer.Outcome = InstallOutcome.Cancelled;
        await f.Service.CheckAsync();
        await f.Service.InstallAsync();
        Assert.Equal(UpdatePhase.Ready, f.Service.State.Phase);
        using var operation = f.Operations.BeginOperation();
    }

    [Fact]
    public async Task MaintenanceWaitsForNestedOperationsAndRejectsNewIndependentOnes()
    {
        var gate = new AppDataOperations();
        var active = gate.BeginOperation();
        var quiesce = gate.QuiesceAsync(TimeSpan.FromSeconds(2), default);
        Assert.False(quiesce.IsCompleted);
        using (gate.BeginOperation()) { } // Existing operations may complete nested work.
        Task independent;
        using (ExecutionContext.SuppressFlow())
            independent = Task.Run(() => Assert.Throws<InvalidOperationException>(() => gate.BeginOperation()));
        await independent;
        active.Dispose();
        using (await quiesce) { }
        using var next = gate.BeginOperation();
    }

    [Fact]
    public async Task FailedDataOperationAbortsMaintenance()
    {
        var gate = new AppDataOperations();
        var active = gate.BeginOperation();
        var quiesce = gate.QuiesceAsync(TimeSpan.FromSeconds(2), default);
        active.Failed();
        active.Dispose();
        await Assert.ThrowsAsync<IOException>(() => quiesce);
        using var next = gate.BeginOperation();
    }

    [Fact]
    public async Task AlreadyFailedOperationCannotBeOverlookedWhileItIsStillUnwinding()
    {
        var gate = new AppDataOperations();
        var operation = gate.BeginOperation();
        operation.Failed();
        var maintenance = gate.QuiesceAsync(TimeSpan.FromSeconds(2), default);
        operation.Dispose();
        await Assert.ThrowsAsync<IOException>(() => maintenance);
    }

    [Fact]
    public async Task FailedNestedWriteRemainsVisibleUntilItsOuterOperationFinishes()
    {
        var gate = new AppDataOperations();
        var outer = gate.BeginOperation();
        using (var inner = gate.BeginOperation()) inner.Failed();
        var maintenance = gate.QuiesceAsync(TimeSpan.FromSeconds(2), default);
        outer.Dispose();
        await Assert.ThrowsAsync<IOException>(() => maintenance);
    }

    [Fact]
    public async Task CompletedOperationContextCannotBypassTheInstallationBarrier()
    {
        var gate = new AppDataOperations();
        ExecutionContext context;
        using (gate.BeginOperation()) context = ExecutionContext.Capture()!;
        using var maintenance = await gate.QuiesceAsync(TimeSpan.FromSeconds(2), default);
        ExecutionContext.Run(context, _ => Assert.Throws<InvalidOperationException>(() => gate.BeginOperation()), null);
    }

    [Fact]
    public async Task TimeoutReleasesMaintenanceBarrier()
    {
        var gate = new AppDataOperations();
        using var active = gate.BeginOperation();
        await Assert.ThrowsAsync<TimeoutException>(() => gate.QuiesceAsync(TimeSpan.FromMilliseconds(20), default));
        Task independent;
        using (ExecutionContext.SuppressFlow()) independent = Task.Run(() => { using var next = gate.BeginOperation(); });
        await independent;
    }

    [Fact]
    public async Task ExistingDataCannotBeTreatedAsFreshInstallation()
    {
        using var f = new Fixture();
        var path = Path.Combine(f.Root, "vault.json.enc");
        Directory.CreateDirectory(f.Root);
        await File.WriteAllBytesAsync(path, f.Bytes);
        await Assert.ThrowsAsync<InvalidDataException>(() => StartupDataGuard.VerifyAsync(f.Root, _ => Task.FromResult<string?>(null)));
        Assert.Equal(f.Bytes, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task FreshStoreSetupCannotReplaceExistingVaultOrAuthenticatorFiles()
    {
        using var f = new Fixture();
        Directory.CreateDirectory(f.Root);
        foreach (var name in StartupDataGuard.DataFiles)
        {
            var path = Path.Combine(f.Root, name);
            StartupDataGuard.RequireNewStore(path);
            await File.WriteAllBytesAsync(path, f.Bytes);
            Assert.Throws<InvalidDataException>(() => StartupDataGuard.RequireNewStore(path));
            Assert.Equal(f.Bytes, await File.ReadAllBytesAsync(path));
        }
    }

    [Fact]
    public async Task UpdatesDoNotModifyExistingDataAndSettingsAcrossVersions()
    {
        using var f = new Fixture();
        Directory.CreateDirectory(f.Root);
        var fixtures = StartupDataGuard.DataFiles.Concat(["preferences.dat", "securestorage.dat"]).ToArray();
        foreach (var name in fixtures) File.WriteAllBytes(Path.Combine(f.Root, name), RandomNumberGenerator.GetBytes(128));
        var before = fixtures.ToDictionary(n => n, n => File.ReadAllBytes(Path.Combine(f.Root, n)));
        var installed = f.Installed;
        foreach (var (version, build) in new[] { ("2.5.9", 159), ("2.6.0", 160), ("2.6.3", 163) })
        {
            var service = f.CreateService(installed);
            f.Feed.Signed = f.Sign(f.Signed.Manifest with { Version = version, BuildNumber = build, ReleaseTag = "v" + version });
            await service.CheckAsync(true);
            await service.InstallAsync();
            foreach (var name in fixtures) Assert.Equal(before[name], File.ReadAllBytes(Path.Combine(f.Root, name)));
            installed = installed with { Version = version, BuildNumber = build };
        }
        Assert.Equal(3, f.Installer.Calls);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "ppp-update-tests-" + Guid.NewGuid().ToString("N"));
        public byte[] Bytes { get; } = RandomNumberGenerator.GetBytes(1024);
        public ReleaseVerifier Verifier { get; }
        public SignedRelease Signed { get; }
        public UpdatePackageCache Cache { get; }
        public InstalledApplication Installed { get; } = new("2.5.8", 158, "android", "universal");
        public Settings Settings { get; } = new();
        public Network Network { get; } = new();
        public Installer Installer { get; } = new();
        public Storage Storage { get; } = new();
        public FakeClock Clock { get; } = new();
        public AppDataOperations Operations { get; } = new();
        public Handler Handler { get; }
        public Feed Feed { get; }
        public AppUpdateService Service { get; }
        private readonly HttpClient _http;
        public Fixture()
        {
            Verifier = new(_key.ExportSubjectPublicKeyInfoPem());
            UpdateArtifact Asset(string platform, string architecture, string kind, string name) => new()
            { Platform = platform, Architecture = architecture, Kind = kind, FileName = name, Size = Bytes.Length, Sha256 = Convert.ToHexString(SHA256.HashData(Bytes)) };
            Signed = Sign(new UpdateManifest { Version = "2.5.9", BuildNumber = 159, ReleaseTag = "v2.5.9", Artifacts =
                [Asset("windows", "x64", "full", "app-full.nupkg"), Asset("windows", "x64", "installer", "app-Setup.exe"), Asset("android", "universal", "apk", "app.apk")] });
            Cache = new(Root, Verifier);
            Handler = new() { Data = Bytes };
            _http = new(Handler);
            Feed = new() { Signed = Signed };
            Service = CreateService();
        }
        public SignedRelease Sign(UpdateManifest manifest)
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, ReleaseVerifier.JsonOptions);
            return Verifier.Verify(bytes, _key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        }
        public AppUpdateService CreateService(InstalledApplication? installed = null) => new(installed ?? Installed, Verifier, Feed, Cache,
            new UpdateDownloader(_http, Cache, Storage), Settings, Network, Installer, Operations, Clock);
        public void Dispose() { _http.Dispose(); _key.Dispose(); if (Directory.Exists(Root)) Directory.Delete(Root, true); }
    }
    private sealed class Settings : IUpdateSettings
    {
        public bool AutomaticChecks { get; set; } = true;
        public bool AutomaticDownloads { get; set; } = true;
        public DateTimeOffset? LastCheckUtc { get; set; }
    }
    private sealed class Network : IUpdateNetworkPolicy
    {
        public bool Online = true, Unmetered = true;
        public bool HasInternet => Online;
        public bool IsUnmetered => Unmetered;
        public event EventHandler? Changed;
        public void Notify() => Changed?.Invoke(this, EventArgs.Empty);
    }
    private sealed class Feed : IUpdateFeed
    {
        public required SignedRelease Signed;
        public Exception? Error;
        public int Calls;
        public TaskCompletionSource? Block;
        public async Task<SignedRelease?> GetLatestAsync(CancellationToken ct)
        { Calls++; if (Block is not null) await Block.Task.WaitAsync(ct); if (Error is not null) throw Error; return Signed; }
    }
    private sealed class Storage : IStorageSpace { public long Bytes = long.MaxValue; public long AvailableBytes(string path) => Bytes; }
    private sealed class Installer : IPlatformUpdateInstaller
    {
        public bool IsSupported => true;
        public int Calls;
        public InstallOutcome Outcome = InstallOutcome.Installed;
        public Task PrepareAsync(UpdateRelease release, string path, CancellationToken ct) => Task.CompletedTask;
        public Task<InstallOutcome> InstallAsync(UpdateRelease release, string path, CancellationToken ct) { Calls++; return Task.FromResult(Outcome); }
    }
    private sealed class Handler : HttpMessageHandler
    {
        public required byte[] Data;
        public int Calls;
        public Action? OnRequest;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        { Calls++; OnRequest?.Invoke(); ct.ThrowIfCancellationRequested(); return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(Data) }); }
    }
    private sealed class FakeClock : TimeProvider
    {
        public DateTimeOffset Now = new(2026, 9, 28, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class RoutingHandler(Func<Uri, byte[]> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(response(request.RequestUri!)) });
    }
}
