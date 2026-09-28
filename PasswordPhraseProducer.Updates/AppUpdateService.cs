using System.Security.Cryptography;

namespace PasswordPhraseProducer.Updates;

public sealed class AppUpdateService(
    InstalledApplication installed, ReleaseVerifier verifier, IUpdateFeed feed, UpdatePackageCache cache,
    UpdateDownloader downloader, IUpdateSettings settings, IUpdateNetworkPolicy network,
    IPlatformUpdateInstaller installer, AppDataOperations operations, TimeProvider? timeProvider = null) : IAppUpdateService
{
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private CancellationTokenSource? _downloadCancellation;
    private bool _initialized;
    private string? _installationConfirmation;
    public UpdateState State { get; private set; } = new(UpdatePhase.Idle);
    public event EventHandler? StateChanged;

    private void SetState(UpdateState state)
    {
        State = state;
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try { await InitializeCoreAsync(cancellationToken); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex) { ReportError(ex); }
        finally { _mutex.Release(); }
    }

    private async Task InitializeCoreAsync(CancellationToken ct)
    {
        if (_initialized) return;
        if (!installer.IsSupported)
        {
            SetState(new(UpdatePhase.Unsupported, Message: "Updates stehen in einer installierten Release-Version zur Verfügung."));
            _initialized = true;
            return;
        }
        var attempt = await cache.ReadInstallationAttemptAsync(ct);
        if (attempt is not null && installed.BuildNumber >= attempt.Manifest.BuildNumber &&
            ReleaseVerifier.ParseVersion(installed.Version) >= ReleaseVerifier.ParseVersion(attempt.Manifest.Version))
        {
            _installationConfirmation = $"Update auf Version {installed.Version} erfolgreich installiert.";
            SetState(new(UpdatePhase.Current, Message: _installationConfirmation));
        }
        var cached = await cache.FindReadyAsync(installed, ct);
        if (cached is not null) SetState(new(UpdatePhase.Ready, cached, 1,
            attempt is not null && _installationConfirmation is null
                ? "Die vorherige Installation wurde nicht abgeschlossen. Du kannst sie erneut starten." : null));
        cache.ClearInstallationAttempt();
        _initialized = true;
    }

    public async Task CheckAsync(bool manual = false, CancellationToken cancellationToken = default)
    {
        if (!await _mutex.WaitAsync(0, cancellationToken)) return;
        var previous = State;
        try
        {
            await InitializeCoreAsync(cancellationToken);
            if (!installer.IsSupported) return;
            if (!manual && (!settings.AutomaticChecks ||
                    settings.LastCheckUtc is { } last && _clock.GetUtcNow() - last < UpdateIdentity.CheckInterval))
            {
                if (settings.AutomaticChecks && settings.AutomaticDownloads && network.HasInternet && network.IsUnmetered &&
                    State.Phase == UpdatePhase.Available && State.Release is { } waiting)
                    await DownloadCoreAsync(waiting, manual: false, cancellationToken);
                return;
            }
            if (!network.HasInternet)
            {
                if (manual) SetState(State with { Message = "Keine Internetverbindung. Heruntergeladene Updates bleiben verfügbar." });
                return;
            }
            previous = State;
            settings.LastCheckUtc = _clock.GetUtcNow();
            SetState(State with { Phase = UpdatePhase.Checking, Message = null });
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            var signed = await feed.GetLatestAsync(timeout.Token);
            var release = signed is null ? null : ReleaseVerifier.Select(verifier.Verify(signed.ManifestBytes, signed.Signature), installed);
            if (release is null)
            {
                SetState(previous.Phase == UpdatePhase.Ready ? previous : new(UpdatePhase.Current, Message: _installationConfirmation ?? "Die App ist aktuell."));
                return;
            }
            // An older/replayed release must never replace a newer, verified cached update.
            if (previous.Release is { } old && old.BuildNumber > release.BuildNumber)
            {
                SetState(previous);
                return;
            }
            try
            {
                await ReleaseVerifier.VerifyPackageAsync(cache.PackagePath(release), release.Artifact, cancellationToken);
                SetState(new(UpdatePhase.Ready, release, 1));
                return;
            }
            catch (Exception ex) when (ex is IOException or CryptographicException or UnauthorizedAccessException) { }
            SetState(new(UpdatePhase.Available, release));
            if (settings.AutomaticDownloads && network.IsUnmetered)
                await DownloadCoreAsync(release, manual: false, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { SetState(previous); }
        catch (Exception ex)
        {
            if (previous.Phase == UpdatePhase.Ready) SetState(previous with { Message = FriendlyMessage(ex) });
            else ReportError(ex);
        }
        finally { _mutex.Release(); }
    }

    public async Task DownloadAsync(bool manual = true, CancellationToken cancellationToken = default)
    {
        if (!await _mutex.WaitAsync(0, cancellationToken)) return;
        try
        {
            if (State.Release is not { } release || !installer.IsSupported) return;
            if (!manual && (!settings.AutomaticDownloads || !network.IsUnmetered)) return;
            await DownloadCoreAsync(release, manual, cancellationToken);
        }
        catch (Exception ex) { ReportError(ex); }
        finally { _mutex.Release(); }
    }

    private async Task DownloadCoreAsync(UpdateRelease release, bool manual, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _downloadCancellation = linked;
        void NetworkChanged(object? sender, EventArgs args)
        {
            if (!network.HasInternet || !manual && !network.IsUnmetered) linked.Cancel();
        }
        network.Changed += NetworkChanged;
        try
        {
            NetworkChanged(null, EventArgs.Empty);
            linked.Token.ThrowIfCancellationRequested();
            SetState(new(UpdatePhase.Downloading, release));
            await downloader.DownloadAsync(release, p => SetState(new(UpdatePhase.Downloading, release, p)), linked.Token);
            SetState(new(UpdatePhase.Ready, release, 1));
        }
        catch (OperationCanceledException)
        {
            SetState(new(UpdatePhase.Available, release, Message: "Download unterbrochen. Du kannst ihn erneut starten."));
        }
        finally
        {
            network.Changed -= NetworkChanged;
            _downloadCancellation = null;
        }
    }

    public void CancelDownload() => _downloadCancellation?.Cancel();

    public async Task InstallAsync(CancellationToken cancellationToken = default)
    {
        if (!await _mutex.WaitAsync(0, cancellationToken)) return;
        var release = State.Release;
        var verifiedPackage = false;
        try
        {
            if (State.Phase != UpdatePhase.Ready || release is null || !installer.IsSupported) return;
            SetState(new(UpdatePhase.Preparing, release, 1));
            var signed = verifier.Verify(release.Signed.ManifestBytes, release.Signed.Signature);
            release = ReleaseVerifier.Select(signed, installed) ?? throw new InvalidDataException("Dieses Update ist nicht neuer als die App.");
            var path = cache.PackagePath(release);
            await ReleaseVerifier.VerifyPackageAsync(path, release.Artifact, cancellationToken);
            verifiedPackage = true;
            await installer.PrepareAsync(release, path, cancellationToken);
            using var maintenance = await operations.QuiesceAsync(TimeSpan.FromSeconds(30), cancellationToken);
            verifiedPackage = false;
            await ReleaseVerifier.VerifyPackageAsync(path, release.Artifact, cancellationToken);
            verifiedPackage = true;
            SetState(new(UpdatePhase.Installing, release, 1));
            await cache.RecordInstallationAttemptAsync(release, cancellationToken);
            var outcome = await installer.InstallAsync(release, path, cancellationToken);
            if (outcome == InstallOutcome.Cancelled) cache.ClearInstallationAttempt();
            SetState(outcome == InstallOutcome.Cancelled
                ? new(UpdatePhase.Ready, release, 1, "Installation abgebrochen. Deine Daten bleiben erhalten.")
                : new(UpdatePhase.Current, Message: "Update installiert. Öffne die App erneut."));
        }
        catch (Exception ex)
        {
            cache.ClearInstallationAttempt();
            SetState(new(verifiedPackage && ex is not CryptographicException ? UpdatePhase.Ready : UpdatePhase.Error,
                release, Message: FriendlyMessage(ex)));
        }
        finally { _mutex.Release(); }
    }

    private void ReportError(Exception ex) => SetState(State with { Phase = UpdatePhase.Error, Message = FriendlyMessage(ex) });
    private static string FriendlyMessage(Exception ex) => ex switch
    {
        CryptographicException => "Sicherheitsprüfung fehlgeschlagen. Das Update wird nicht installiert.",
        OperationCanceledException => "Der Vorgang wurde abgebrochen oder hat zu lange gedauert. Bitte erneut versuchen.",
        TimeoutException => "Der Vorgang hat zu lange gedauert. Das Update wurde abgebrochen; bitte erneut versuchen.",
        HttpRequestException => "GitHub ist gerade nicht erreichbar. Bitte später erneut versuchen.",
        UnauthorizedAccessException => "Der Zugriff wurde verweigert. Bitte Berechtigungen prüfen.",
        IOException or InvalidOperationException => ex.Message,
        _ => "Das Update konnte nicht verarbeitet werden. Bitte später erneut versuchen."
    };
}
