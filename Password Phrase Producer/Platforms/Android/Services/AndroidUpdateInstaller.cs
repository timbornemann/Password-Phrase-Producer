using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using Android.Provider;
using PasswordPhraseProducer.Updates;

namespace Password_Phrase_Producer.Platforms.Android.Services;

public sealed class AndroidUpdateInstaller : IPlatformUpdateInstaller
{
    private static TaskCompletionSource? _permissionReturned;
    private static TaskCompletionSource<InstallOutcome>? _installation;
    private static int? _sessionId;
    private readonly Context _context = global::Android.App.Application.Context;
    public static string? RecoveryError { get; private set; }

    public static void RecoverInterruptedSessions()
    {
        if (_installation is not null) return; // Activity recreation in the same process keeps the active barrier.
        // A process may die while the system confirmation dialog is still open. Abandon its
        // sessions before allowing vault operations in a new process; an old dialog must not
        // unexpectedly replace the process while it is writing new data.
        try
        {
            var context = global::Android.App.Application.Context;
            var installer = context.PackageManager!.PackageInstaller!;
            foreach (var session in installer.MySessions!)
                if (session.AppPackageName == context.PackageName)
                    installer.AbandonSession(session.SessionId);
            RecoveryError = null;
        }
        catch { RecoveryError = "Eine vorherige Android-Installation wird noch abgeschlossen. Bitte öffne die App anschließend erneut."; }
    }

    public bool IsSupported =>
#if DEBUG
        false;
#else
        true;
#endif

    public static void OnActivityResumed() => _permissionReturned?.TrySetResult();

    public async Task PrepareAsync(UpdateRelease release, string packagePath, CancellationToken cancellationToken)
    {
        VerifyApk(packagePath, release.BuildNumber);
        if (Build.VERSION.SdkInt >= BuildVersionCodes.O && !_context.PackageManager!.CanRequestPackageInstalls())
        {
            _permissionReturned = new(TaskCreationOptions.RunContinuationsAsynchronously);
            try
            {
                await MainThread.InvokeOnMainThreadAsync(() =>
                {
                    var intent = new Intent(Settings.ActionManageUnknownAppSources,
                        global::Android.Net.Uri.Parse("package:" + _context.PackageName));
                    Platform.CurrentActivity!.StartActivity(intent);
                });
                await _permissionReturned.Task.WaitAsync(TimeSpan.FromMinutes(5), cancellationToken);
                if (!_context.PackageManager.CanRequestPackageInstalls())
                    throw new InvalidOperationException("Bitte erlaube der App unter ‚Aus dieser Quelle zulassen‘ die Installation von Updates.");
            }
            finally { _permissionReturned = null; }
        }
    }

    private void VerifyApk(string path, long buildNumber)
    {
        var manager = _context.PackageManager!;
#pragma warning disable CS0618, CA1422
        var apk = manager.GetPackageArchiveInfo(path, PackageInfoFlags.Signatures)
            ?? throw new InvalidDataException("Die APK kann nicht gelesen werden.");
        var current = manager.GetPackageInfo(_context.PackageName!, PackageInfoFlags.Signatures)!;
        var apkVersion = Build.VERSION.SdkInt >= BuildVersionCodes.P ? apk.LongVersionCode : apk.VersionCode;
        var installedVersion = Build.VERSION.SdkInt >= BuildVersionCodes.P ? current.LongVersionCode : current.VersionCode;
        if (apk.PackageName != UpdateIdentity.AndroidPackageId || apk.PackageName != current.PackageName ||
            apkVersion != buildNumber || apkVersion <= installedVersion)
            throw new InvalidDataException("Die APK passt nicht zu dieser App oder ist nicht neuer.");
        var expected = current.Signatures?.Select(s => Convert.ToHexString(s.ToByteArray()!)).Order().ToArray();
        var actual = apk.Signatures?.Select(s => Convert.ToHexString(s.ToByteArray()!)).Order().ToArray();
#pragma warning restore CS0618, CA1422
        if (expected is not { Length: > 0 } || actual is null || !expected.SequenceEqual(actual))
            throw new System.Security.Cryptography.CryptographicException("Die APK wurde mit einem anderen Schlüssel signiert.");
    }

    public async Task<InstallOutcome> InstallAsync(UpdateRelease release, string packagePath, CancellationToken cancellationToken)
    {
        VerifyApk(packagePath, release.BuildNumber);
        var installer = _context.PackageManager!.PackageInstaller!;
        using var parameters = new PackageInstaller.SessionParams(PackageInstallMode.FullInstall);
        parameters.SetAppPackageName(_context.PackageName);
        parameters.SetSize(release.Artifact.Size);
        if (Build.VERSION.SdkInt >= BuildVersionCodes.S)
            parameters.SetRequireUserAction((int)PackageInstallUserAction.Required);
        var id = installer.CreateSession(parameters);
        _sessionId = id;
        _installation = new(TaskCreationOptions.RunContinuationsAsynchronously);
        try
        {
            using var session = installer.OpenSession(id)!;
            await using (var input = File.OpenRead(packagePath))
            using (var output = session.OpenWrite("base.apk", 0, release.Artifact.Size)!)
            {
                await input.CopyToAsync(output, cancellationToken);
                session.Fsync(output);
            }
            var callback = new Intent(_context, typeof(UpdateInstallReceiver));
            callback.PutExtra("ppp.session", id);
            var flags = PendingIntentFlags.UpdateCurrent;
            if (Build.VERSION.SdkInt >= BuildVersionCodes.S) flags |= PendingIntentFlags.Mutable;
            using var pending = PendingIntent.GetBroadcast(_context, id, callback, flags)!;
            session.Commit(pending.IntentSender);
            // The data-operation barrier remains held until failure/cancellation or process replacement.
            return await _installation.Task;
        }
        catch
        {
            try { installer.AbandonSession(id); } catch (Exception) { }
            throw;
        }
        finally
        {
            _installation = null;
            _sessionId = null;
        }
    }

    internal static void HandleResult(Context context, Intent intent)
    {
        if (_installation is null || intent.GetIntExtra("ppp.session", -1) != _sessionId) return;
        var status = (PackageInstallStatus)intent.GetIntExtra(PackageInstaller.ExtraStatus, (int)PackageInstallStatus.Failure);
        if (status == PackageInstallStatus.PendingUserAction)
        {
#pragma warning disable CS0618, CA1422
            var confirmation = intent.GetParcelableExtra(Intent.ExtraIntent) as Intent;
#pragma warning restore CS0618, CA1422
            if (confirmation is null) _installation.TrySetException(new InvalidOperationException("Der Installationsdialog konnte nicht geöffnet werden."));
            else
            {
                confirmation.AddFlags(ActivityFlags.NewTask);
                try { context.StartActivity(confirmation); }
                catch (Exception ex) { _installation.TrySetException(ex); }
            }
        }
        else if (status == PackageInstallStatus.Success) _installation.TrySetResult(InstallOutcome.Installed);
        else if (status == PackageInstallStatus.FailureAborted) _installation.TrySetResult(InstallOutcome.Cancelled);
        else _installation.TrySetException(new InvalidOperationException(status == PackageInstallStatus.FailureStorage
            ? "Android hat nicht genügend Speicher für das Update."
            : "Android konnte das Update nicht installieren. Die bisherige App und ihre Daten bleiben erhalten."));
    }
}

[BroadcastReceiver(Enabled = true, Exported = false)]
public sealed class UpdateInstallReceiver : BroadcastReceiver
{
    public override void OnReceive(Context? context, Intent? intent)
    {
        if (context is not null && intent is not null) AndroidUpdateInstaller.HandleResult(context, intent);
    }
}
