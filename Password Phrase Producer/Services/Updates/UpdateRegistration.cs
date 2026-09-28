using System.Reflection;
using PasswordPhraseProducer.Updates;
using Password_Phrase_Producer.ViewModels;

namespace Password_Phrase_Producer.Services.Updates;

public static class UpdateRegistration
{
    public static void AddAppUpdates(this IServiceCollection services)
    {
        var assembly = typeof(UpdateRegistration).Assembly;
        string Metadata(string key) => assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .SingleOrDefault(a => a.Key == key)?.Value ?? "";
        var version = Metadata("PasswordPhraseProducer.ReleaseVersion");
        // Local development builds may still use the project's historic two-part version.
        if (version.Count(c => c == '.') == 1) version += ".0";
        _ = long.TryParse(Metadata("PasswordPhraseProducer.BuildNumber"), out var build);
        var platform = DeviceInfo.Platform == DevicePlatform.WinUI ? "windows" : "android";
        services.AddSingleton(new InstalledApplication(version, build, platform, platform == "windows" ? "x64" : "universal"));
        using var stream = assembly.GetManifestResourceStream("UpdateSigningPublicKey.pem")
            ?? throw new InvalidOperationException("Der öffentliche Update-Schlüssel fehlt.");
        using var reader = new StreamReader(stream);
        var verifier = new ReleaseVerifier(reader.ReadToEnd());
        services.AddSingleton(verifier);
        services.AddSingleton(AppDataOperations.Shared);
        services.AddSingleton<IUpdateSettings, UpdateSettings>();
        services.AddSingleton<IUpdateNetworkPolicy, UpdateNetworkPolicy>();
        services.AddSingleton<IStorageSpace, UpdateStorageSpace>();
        services.AddSingleton(new HttpClient { Timeout = TimeSpan.FromMinutes(20) });
        services.AddSingleton(new UpdatePackageCache(Path.Combine(FileSystem.CacheDirectory, "updates"), verifier));
        services.AddSingleton<IUpdateFeed, GitHubUpdateFeed>();
        services.AddSingleton<UpdateDownloader>();
#if WINDOWS
        services.AddSingleton<IPlatformUpdateInstaller, Platforms.Windows.Services.WindowsUpdateInstaller>();
#elif ANDROID
        services.AddSingleton<IPlatformUpdateInstaller, Platforms.Android.Services.AndroidUpdateInstaller>();
#else
        services.AddSingleton<IPlatformUpdateInstaller, UnsupportedInstaller>();
#endif
        services.AddSingleton<IAppUpdateService, AppUpdateService>();
        services.AddSingleton<UpdateLifecycle>();
        services.AddSingleton<UpdateSettingsViewModel>();
    }

    private sealed class UnsupportedInstaller : IPlatformUpdateInstaller
    {
        public bool IsSupported => false;
        public Task PrepareAsync(UpdateRelease release, string path, CancellationToken ct) => throw new NotSupportedException();
        public Task<InstallOutcome> InstallAsync(UpdateRelease release, string path, CancellationToken ct) => throw new NotSupportedException();
    }
}
