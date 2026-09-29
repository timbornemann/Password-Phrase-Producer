using System.ComponentModel;
using CommunityToolkit.Maui.Views;
using Password_Phrase_Producer.Views.Dialogs;
using PasswordPhraseProducer.Updates;

namespace Password_Phrase_Producer.ViewModels;

public sealed class UpdateSettingsViewModel : INotifyPropertyChanged
{
    private readonly IAppUpdateService _updates;
    private readonly IUpdateSettings _settings;
    private string? _settingsError;
    public event PropertyChangedEventHandler? PropertyChanged;
    public string InstalledVersion { get; }
    public string AvailableVersion => _updates.State.Release?.Version ?? "–";
    public string LastCheck => _settings.LastCheckUtc?.ToLocalTime().ToString("g") ?? "Noch nicht geprüft";
    public string Notes => _updates.State.Release?.Signed.Manifest.Notes ?? "";
    public bool HasNotes => !string.IsNullOrWhiteSpace(Notes);
    public string DownloadSize => _updates.State.Release is { } release ? $"{release.Artifact.Size / 1048576d:F1} MB" : "";
    public double Progress => _updates.State.Progress;
    public bool IsDownloading => _updates.State.Phase == UpdatePhase.Downloading;
    public bool CanChangeSettings => _updates.State.Phase is not (UpdatePhase.Preparing or UpdatePhase.Installing);
    public bool CanCheck => _updates.State.Phase is not (UpdatePhase.Checking or UpdatePhase.Downloading or UpdatePhase.Preparing or UpdatePhase.Installing or UpdatePhase.Unsupported);
    public bool CanDownload => _updates.State.Release is not null && _updates.State.Phase is UpdatePhase.Available or UpdatePhase.Error;
    public bool CanInstall => _updates.State.Phase == UpdatePhase.Ready;
    public bool HasUpdate => _updates.State.Release is not null;
    public string InstallText => DeviceInfo.Platform == DevicePlatform.WinUI ? "Aktualisieren und neu starten" : "Update installieren";
    public string CheckText => _updates.State.Phase == UpdatePhase.Error ? "Erneut versuchen" : "Nach Updates suchen";
    public string Status => _settingsError ?? _updates.State.Message ?? _updates.State.Phase switch
    {
        UpdatePhase.Checking => "Suche nach Updates …",
        UpdatePhase.Current => "Die App ist aktuell.",
        UpdatePhase.Available => "Update verfügbar. Automatischer Download nur über ungetaktete Verbindungen.",
        UpdatePhase.Downloading => $"Update wird geladen … {_updates.State.Progress:P0}",
        UpdatePhase.Ready => "Update bereit. Die Installation startet erst nach deinem Klick.",
        UpdatePhase.Preparing => "Installation wird vorbereitet; laufende Speichervorgänge werden abgeschlossen …",
        UpdatePhase.Installing => "Update wird installiert …",
        _ => "Updates werden während der App-Nutzung automatisch geprüft."
    };
    public bool AutomaticChecks
    {
        get => _settings.AutomaticChecks;
        set
        {
            if (!CanChangeSettings) return;
            try { _settings.AutomaticChecks = value; _settingsError = null; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { _settingsError = "Die Update-Einstellungen konnten nicht gespeichert werden."; }
            Changed();
        }
    }
    public bool AutomaticDownloads
    {
        get => _settings.AutomaticDownloads;
        set
        {
            if (!CanChangeSettings) return;
            try { _settings.AutomaticDownloads = value; _settingsError = null; if (!value) _updates.CancelDownload(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { _settingsError = "Die Update-Einstellungen konnten nicht gespeichert werden."; }
            Changed();
        }
    }
    public Command CheckCommand { get; }
    public Command DownloadCommand { get; }
    public Command InstallCommand { get; }
    public Command ReleaseNotesCommand { get; }

    public UpdateSettingsViewModel(IAppUpdateService updates, IUpdateSettings settings, InstalledApplication installed)
    {
        _updates = updates;
        _settings = settings;
        InstalledVersion = installed.Version;
        CheckCommand = new Command(async () => await updates.CheckAsync(manual: true), () => CanCheck);
        DownloadCommand = new Command(async () => await updates.DownloadAsync(), () => CanDownload);
        InstallCommand = new Command(async () => await updates.InstallAsync(), () => CanInstall);
        ReleaseNotesCommand = new Command(async () =>
        {
            if (updates.State.Release is not { } release) return;
            var notes = release.Signed.Manifest.Notes;
            if (string.IsNullOrWhiteSpace(notes)) return;
            if (Application.Current?.Windows.FirstOrDefault()?.Page is not Page page) return;
            var releaseUri = new Uri($"https://github.com/{UpdateIdentity.Repository}/releases/tag/{Uri.EscapeDataString(release.Signed.Manifest.ReleaseTag)}");
            await page.ShowPopupAsync(new ReleaseNotesPopup(notes, release.Version, releaseUri));
        });
        updates.StateChanged += (_, _) => MainThread.BeginInvokeOnMainThread(Changed);
    }

    private void Changed()
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(null));
        CheckCommand.ChangeCanExecute();
        DownloadCommand.ChangeCanExecute();
        InstallCommand.ChangeCanExecute();
    }
}
