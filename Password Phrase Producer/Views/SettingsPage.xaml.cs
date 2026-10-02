using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Maui.Storage;
using CommunityToolkit.Maui.Views;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Storage;
using Microsoft.Maui.Devices;
using Password_Phrase_Producer.ViewModels;
using Password_Phrase_Producer.Views.Dialogs;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.LocalTransfer;
using Password_Phrase_Producer.Services.Vault;
using System.Security.Cryptography;
using Password_Phrase_Producer.PasswordGenerationTechniques.DicewareTechnique;
using Password_Phrase_Producer.Views.Security;

namespace Password_Phrase_Producer.Views;

public partial class SettingsPage : ContentPage
{
    private readonly VaultSettingsViewModel _viewModel;
    private readonly IRecoveryQuestionsService _recoveryQuestions;
    private readonly IUnlockAttemptGate _attemptGate;
    private readonly LocalTransferActivity _localTransferActivity;
    private readonly IAppLockService _appLock;
    private readonly PasswordVaultService _passwordVault;
    private readonly DataVaultService _dataVault;
    private readonly TotpEncryptionService _authenticator;
    private LoadingPage? _loadingPage;
    private bool _recoverySettingsBusy;
    private bool _localTransferBusy;

    public SettingsPage(VaultSettingsViewModel viewModel, UpdateSettingsViewModel updates,
        IRecoveryQuestionsService recoveryQuestions, IUnlockAttemptGate attemptGate,
        LocalTransferActivity localTransferActivity, IAppLockService appLock,
        PasswordVaultService passwordVault, DataVaultService dataVault, TotpEncryptionService authenticator)
    {
        InitializeComponent();
        BindingContext = _viewModel = viewModel;
        UpdatePanel.BindingContext = updates;
        _recoveryQuestions = recoveryQuestions;
        _attemptGate = attemptGate;
        _localTransferActivity = localTransferActivity;
        _appLock = appLock;
        _passwordVault = passwordVault;
        _dataVault = dataVault;
        _authenticator = authenticator;
        LocalTransferSection.IsVisible = DeviceInfo.Platform == DevicePlatform.WinUI ||
                                         DeviceInfo.Platform == DevicePlatform.Android;
        ShowSettingsCategory("security");
        ShowVaultPasswordCategory("password");
    }

    private async void OnSettingsCategoryClicked(object? sender, EventArgs e)
    {
        if (sender is not Button button || button.CommandParameter is not string category)
            return;

        ShowSettingsCategory(category);
        await SettingsScroll.ScrollToAsync(0, 0, false);
    }

    private void ShowSettingsCategory(string category)
    {
        SecuritySettingsSection.IsVisible = category == "security";
        VaultSettingsSection.IsVisible = category == "vaults";
        DataSettingsSection.IsVisible = category == "data";
        AppSettingsSection.IsVisible = category == "app";

        SettingsSectionTitle.Text = category switch
        {
            "vaults" => "Tresor-Passwörter",
            "data" => "Daten & Synchronisation",
            "app" => "App & Updates",
            _ => "Zugriff & Sicherheit"
        };

        foreach (var (tab, key) in new[]
        {
            (SecurityTab, "security"), (VaultTab, "vaults"),
            (DataTab, "data"), (AppTab, "app")
        })
        {
            var selected = key == category;
            tab.BackgroundColor = Microsoft.Maui.Graphics.Color.FromArgb(selected ? "#2B343D" : "#171C21");
            tab.TextColor = Microsoft.Maui.Graphics.Color.FromArgb(selected ? "#F7F8F9" : "#9EAAB5");
            tab.BorderColor = Microsoft.Maui.Graphics.Color.FromArgb(selected ? "#536D81" : "#313B44");
            tab.BorderWidth = 1;
        }
    }

    private void OnVaultCategoryClicked(object? sender, EventArgs e)
    {
        if (sender is Button { CommandParameter: string category })
            ShowVaultPasswordCategory(category);
    }

    private void ShowVaultPasswordCategory(string category)
    {
        PasswordVaultSettingsCard.IsVisible = category == "password";
        DataVaultSettingsCard.IsVisible = category == "data";
        AuthenticatorSettingsCard.IsVisible = category == "authenticator";

        foreach (var (tab, key) in new[]
        {
            (PasswordVaultTab, "password"), (DataVaultTab, "data"),
            (AuthenticatorTab, "authenticator")
        })
        {
            var selected = key == category;
            tab.BackgroundColor = Microsoft.Maui.Graphics.Color.FromArgb(selected ? "#2B343D" : "#171C21");
            tab.TextColor = Microsoft.Maui.Graphics.Color.FromArgb(selected ? "#F7F8F9" : "#9EAAB5");
            tab.BorderColor = Microsoft.Maui.Graphics.Color.FromArgb(selected ? "#536D81" : "#313B44");
            tab.BorderWidth = 1;
        }
    }

    private async void OnConfigureRecoveryClicked(object? sender, EventArgs e)
    {
        if (_recoverySettingsBusy) return;
        _recoverySettingsBusy = true;
        try
        {
            await _viewModel.InitializeAsync();
            if (!await EnsureVaultUnlockedAsync() || !await EnsureDataVaultUnlockedAsync() ||
                !await EnsureAuthenticatorUnlockedAsync()) return;

            var page = new RecoverySettingsPage(_recoveryQuestions, _attemptGate);
            await Navigation.PushModalAsync(page);
            await page.WaitForCloseAsync();
        }
        catch (Exception ex) { await DisplayAlert("Sicherheitsfragen", ex.Message, "OK"); }
        finally { _viewModel.LockAllVaults(); _recoverySettingsBusy = false; }
    }

    private async Task<bool> EnsureVaultUnlockedAsync()
    {
        if (!_viewModel.IsPasswordVaultConfigured)
            return true;
        if (_viewModel.IsVaultUnlocked)
        {
            return true;
        }
        if (!await EnsureAttemptsAvailableAsync(ProtectedAccess.PasswordVault)) return false;

        var promptPage = new PasswordPromptPage(
            "Passwort-Tresor entsperren",
            "Gib dein Master-Passwort ein, um fortzufahren.",
            "Entsperren",
            "Abbrechen");

        await Navigation.PushModalAsync(promptPage);
        var password = await promptPage.WaitForResultAsync();
        await Navigation.PopModalAsync();

        if (string.IsNullOrEmpty(password))
        {
            return false;
        }

        var success = await _viewModel.UnlockVaultWithPasswordAsync(password);
        if (!success)
        {
            await ShowUnlockFailureAsync(ProtectedAccess.PasswordVault);
            return false;
        }

        await _viewModel.RefreshVaultStateAsync();
        return true;
    }

    private async Task<bool> EnsureVaultUnlockedWithoutSyncAsync()
    {
        if (_viewModel.IsVaultUnlocked)
        {
            return true;
        }
        if (!await EnsureAttemptsAvailableAsync(ProtectedAccess.PasswordVault)) return false;

        var promptPage = new PasswordPromptPage(
            "Passwort-Tresor entsperren",
            "Gib dein Master-Passwort ein, um fortzufahren.",
            "Entsperren",
            "Abbrechen");

        await Navigation.PushModalAsync(promptPage);
        var password = await promptPage.WaitForResultAsync();
        await Navigation.PopModalAsync();

        if (string.IsNullOrEmpty(password))
        {
            return false;
        }

        var success = await _viewModel.UnlockVaultWithoutSyncAsync(password);
        if (!success)
        {
            await ShowUnlockFailureAsync(ProtectedAccess.PasswordVault);
            return false;
        }

        await _viewModel.RefreshVaultStateAsync();
        return true;
    }

    private async Task<bool> EnsureDataVaultUnlockedAsync()
    {
        if (!_viewModel.IsDataVaultConfigured)
            return true;
        if (_viewModel.IsDataVaultUnlocked)
        {
            return true;
        }
        if (!await EnsureAttemptsAvailableAsync(ProtectedAccess.DataVault)) return false;

        var promptPage = new PasswordPromptPage(
            "Datentresor entsperren",
            "Gib dein Master-Passwort ein, um fortzufahren.",
            "Entsperren",
            "Abbrechen");

        await Navigation.PushModalAsync(promptPage);
        var password = await promptPage.WaitForResultAsync();
        await Navigation.PopModalAsync();

        if (string.IsNullOrEmpty(password))
        {
            return false;
        }

        var success = await _viewModel.UnlockDataVaultWithPasswordAsync(password);
        if (!success)
        {
            await ShowUnlockFailureAsync(ProtectedAccess.DataVault);
            return false;
        }

        await _viewModel.RefreshDataVaultStateAsync();
        return true;
    }

    private async Task<bool> EnsureDataVaultUnlockedWithoutSyncAsync()
    {
        if (_viewModel.IsDataVaultUnlocked)
        {
            return true;
        }
        if (!await EnsureAttemptsAvailableAsync(ProtectedAccess.DataVault)) return false;

        var promptPage = new PasswordPromptPage(
            "Datentresor entsperren",
            "Gib dein Master-Passwort ein, um fortzufahren.",
            "Entsperren",
            "Abbrechen");

        await Navigation.PushModalAsync(promptPage);
        var password = await promptPage.WaitForResultAsync();
        await Navigation.PopModalAsync();

        if (string.IsNullOrEmpty(password))
        {
            return false;
        }

        var success = await _viewModel.UnlockDataVaultWithoutSyncAsync(password);
        if (!success)
        {
            await ShowUnlockFailureAsync(ProtectedAccess.DataVault);
            return false;
        }

        await _viewModel.RefreshDataVaultStateAsync();
        return true;
    }

    private async Task<bool> EnsureAuthenticatorUnlockedAsync()
    {
        if (_viewModel.IsAuthenticatorUnlocked) return true;
        if (!_viewModel.HasAuthenticatorPassword)
        {
            return true; // No password set, consider it unlocked
        }
        if (!await EnsureAttemptsAvailableAsync(ProtectedAccess.Authenticator)) return false;

        var promptPage = new PasswordPromptPage(
            "Authenticator entsperren",
            "Gib dein Authenticator-Passwort ein, um fortzufahren.",
            "Entsperren",
            "Abbrechen");

        await Navigation.PushModalAsync(promptPage);
        var password = await promptPage.WaitForResultAsync();
        await Navigation.PopModalAsync();

        if (string.IsNullOrEmpty(password))
        {
            return false;
        }

        var success = await _viewModel.UnlockAuthenticatorWithPasswordAsync(password);
        if (!success)
        {
            await ShowUnlockFailureAsync(ProtectedAccess.Authenticator);
            return false;
        }

        return true;
    }

    private async Task<bool> EnsureAttemptsAvailableAsync(ProtectedAccess access)
    {
        var status = await _attemptGate.GetStatusAsync(access);
        if (!status.IsLocked) return true;
        await DisplayAlert("Vorübergehend gesperrt",
            $"Dieser Zugang ist bis {status.LockedUntil!.Value.ToLocalTime():g} gesperrt. Öffne den Tresor nach Ablauf der Wartezeit oder nutze dort den einmaligen Notzugang.", "OK");
        return false;
    }

    private async Task ShowUnlockFailureAsync(ProtectedAccess access)
    {
        var status = await _attemptGate.GetStatusAsync(access);
        await DisplayAlert(status.IsLocked ? "Vorübergehend gesperrt" : "Passwort ungültig",
            status.IsLocked ? $"Erneut versuchen ab {status.LockedUntil!.Value.ToLocalTime():g}." :
                $"Noch {status.PasswordAttemptsRemaining} Passwortversuche.", "OK");
    }

    private async Task<bool?> AskMergeOrReplaceAsync()
    {
        var result = await DisplayActionSheet(
            "Import-Modus wählen",
            "Abbrechen",
            null,
            "Zusammenführen (Merge)",
            "Ersetzen");

        return result switch
        {
            "Zusammenführen (Merge)" => true,
            "Ersetzen" => false,
            _ => null
        };
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        _viewModel.Activate();

        // Run initialization in background to avoid blocking UI thread
        _ = Task.Run(async () =>
        {
            try
            {
                await _viewModel.InitializeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Log error and show user-friendly message
                System.Diagnostics.Debug.WriteLine($"Error initializing settings page: {ex}");
                await MainThread.InvokeOnMainThreadAsync(async () =>
                {
                    await DisplayAlert("Fehler", "Die Einstellungen konnten nicht geladen werden. Bitte versuche es erneut.", "OK");
                }).ConfigureAwait(false);
            }
        });
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _viewModel.Deactivate();
    }

    private async void OnBackTapped(object? sender, TappedEventArgs e)
    {
        if (Shell.Current is not null)
        {
            await Shell.Current.GoToAsync("//home");
        }
    }

    protected override bool OnBackButtonPressed()
    {
        Dispatcher.Dispatch(async () =>
        {
            if (Shell.Current is not null)
            {
                await Shell.Current.GoToAsync("//home");
            }
        });
        return true;
    }

    private void OnOpenFlyoutTapped(object? sender, TappedEventArgs e)
    {
        if (Shell.Current is not null)
        {
            Shell.Current.FlyoutIsPresented = true;
        }
    }

    private async void OnExportFullBackupClicked(object? sender, EventArgs e)
    {
        await ShowLoadingPageAsync("Exportiere Daten...");

        try
        {
            await ExecuteSettingsActionAsync(async () =>
            {
                // Unlock all components that have passwords configured
                if (!await EnsureVaultUnlockedAsync())
                {
                    return;
                }

                if (!await EnsureDataVaultUnlockedAsync())
                {
                    return;
                }

                if (!await EnsureAuthenticatorUnlockedAsync())
                {
                    return;
                }

                try
                {
                    await ExportFullBackupAsync();
                }
                finally
                {
                    // Lock all vaults after export
                    _viewModel.LockAllVaults();
                }
            });
        }
        finally
        {
            await HideLoadingPageAsync();
        }
    }

    private async void OnImportFullBackupClicked(object? sender, EventArgs e)
    {
        await ShowLoadingPageAsync("Importiere Daten...");
        bool success = false;

        try
        {
            await ExecuteSettingsActionAsync(async () =>
            {
                // Unlock all components that have passwords configured
                if (!await EnsureVaultUnlockedAsync())
                {
                    return;
                }

                if (!await EnsureDataVaultUnlockedAsync())
                {
                    return;
                }

                if (!await EnsureAuthenticatorUnlockedAsync())
                {
                    return;
                }

                try
                {
                    success = await ImportFullBackupAsync();
                    if (success)
                    {
                        await _viewModel.RefreshVaultStateAsync();
                        await _viewModel.RefreshDataVaultStateAsync();
                    }
                }
                finally
                {
                    // Lock all vaults after import
                    _viewModel.LockAllVaults();
                }
            });
        }
        finally
        {
            await HideLoadingPageAsync();
        }

        if (success)
        {
            var successPopup = new SuccessPopup("Erfolg", "Das Gesamtbackup wurde erfolgreich importiert.", "OK");
            await this.ShowPopupAsync(successPopup);
        }
    }


    private async Task ExportBackupAsync()
    {
        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib ein Passwort zum Verschlüsseln der Export-Datei ein:",
            "Export",
            "Abbrechen", showStrengthMeter: true);

        if (string.IsNullOrEmpty(filePassword))
        {
            return;
        }

        var backupBytes = await _viewModel.ExportWithFilePasswordAsync(filePassword);
        await using var stream = new MemoryStream(backupBytes);
        var result = await FileSaver.Default.SaveAsync("vault-export.json.enc", stream, CancellationToken.None);
        if (!result.IsSuccessful && result.Exception is not null)
        {
            throw new InvalidOperationException(result.Exception.Message, result.Exception);
        }
    }

    private async Task ImportBackupAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Export-Datei auswählen"
        });

        if (file is null)
        {
            return;
        }

        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib das Passwort der Export-Datei ein:",
            "Import",
            "Abbrechen");

        if (string.IsNullOrEmpty(filePassword))
        {
            return;
        }

        await using var stream = await file.OpenReadAsync();
        await _viewModel.ImportWithFilePasswordAsync(stream, filePassword);
    }

    private async Task ExportDataVaultBackupAsync()
    {
        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib ein Passwort zum Verschlüsseln der Export-Datei ein:",
            "Export",
            "Abbrechen", showStrengthMeter: true);

        if (string.IsNullOrEmpty(filePassword))
        {
            return;
        }

        var backupBytes = await _viewModel.ExportDataVaultWithFilePasswordAsync(filePassword);
        await using var stream = new MemoryStream(backupBytes);
        var result = await FileSaver.Default.SaveAsync("data-vault-export.json.enc", stream, CancellationToken.None);
        if (!result.IsSuccessful && result.Exception is not null)
        {
            throw new InvalidOperationException(result.Exception.Message, result.Exception);
        }
    }

    private async Task ImportDataVaultBackupAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Export-Datei auswählen"
        });

        if (file is null)
        {
            return;
        }

        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib das Passwort der Export-Datei ein:",
            "Import",
            "Abbrechen");

        if (string.IsNullOrEmpty(filePassword))
        {
            return;
        }

        await using var stream = await file.OpenReadAsync();
        await _viewModel.ImportDataVaultWithFilePasswordAsync(stream, filePassword);
    }

    private async Task ExportEncryptedAsync()
    {
        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib ein Passwort zum Verschlüsseln der Export-Datei ein:",
            "Export",
            "Abbrechen", showStrengthMeter: true);

        if (string.IsNullOrEmpty(filePassword))
        {
            return;
        }

        var bytes = await _viewModel.ExportWithFilePasswordAsync(filePassword);
        await using var stream = new MemoryStream(bytes);
        var result = await FileSaver.Default.SaveAsync("vault-export.json.enc", stream, CancellationToken.None);
        if (!result.IsSuccessful && result.Exception is not null)
        {
            throw new InvalidOperationException(result.Exception.Message, result.Exception);
        }
    }

    private async Task ImportEncryptedAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Export-Datei auswählen"
        });

        if (file is null)
        {
            return;
        }

        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib das Passwort der Export-Datei ein:",
            "Import",
            "Abbrechen");

        if (string.IsNullOrEmpty(filePassword))
        {
            return;
        }

        await using var stream = await file.OpenReadAsync();
        await _viewModel.ImportWithFilePasswordAsync(stream, filePassword);
    }

    private async Task ExportDataVaultEncryptedAsync()
    {
        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib ein Passwort zum Verschlüsseln der Export-Datei ein:",
            "Export",
            "Abbrechen", showStrengthMeter: true);

        if (string.IsNullOrEmpty(filePassword))
        {
            return;
        }

        var bytes = await _viewModel.ExportDataVaultWithFilePasswordAsync(filePassword);
        await using var stream = new MemoryStream(bytes);
        var result = await FileSaver.Default.SaveAsync("data-vault-export.json.enc", stream, CancellationToken.None);
        if (!result.IsSuccessful && result.Exception is not null)
        {
            throw new InvalidOperationException(result.Exception.Message, result.Exception);
        }
    }



    private async Task ExportFullBackupAsync()
    {
        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib ein Passwort zum Verschlüsseln des Gesamtbackups ein:",
            "Export",
            "Abbrechen", showStrengthMeter: true);

        if (string.IsNullOrEmpty(filePassword))
        {
            return;
        }

        var bytes = await _viewModel.CreateFullBackupAsync(filePassword);
        await using var stream = new MemoryStream(bytes);
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HHmmss");
        var result = await FileSaver.Default.SaveAsync($"full-backup-{timestamp}.json.enc", stream, CancellationToken.None);
        if (!result.IsSuccessful && result.Exception is not null)
        {
            throw new InvalidOperationException(result.Exception.Message, result.Exception);
        }
    }

    private async Task<bool> ImportFullBackupAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Gesamtbackup auswählen"
        });

        if (file is null)
        {
            return false;
        }

        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib das Passwort des Gesamtbackups ein:",
            "Import",
            "Abbrechen");

        if (string.IsNullOrEmpty(filePassword))
        {
            return false;
        }

        await using var stream = await file.OpenReadAsync();
        return await _viewModel.RestoreFullBackupAsync(stream, filePassword,
            () => DisplayAlert("Älteres Gesamtbackup",
                "Dieses Backup schützt die Liste seiner Tresore nicht gegen nachträgliches Entfernen. Importiere es nur, wenn du seiner Herkunft und Vollständigkeit vertraust.",
                "Trotzdem importieren", "Abbrechen"));
    }

    private async void OnLocalSendClicked(object? sender, EventArgs e)
    {
        if (_localTransferBusy) return;
        _localTransferBusy = true;
        byte[]? backup = null;
        var activity = _localTransferActivity.Begin();
        try
        {
            if (!_appLock.IsUnlocked) throw new OperationCanceledException();
            await _viewModel.InitializeAsync();
            if (!_viewModel.IsPasswordVaultConfigured && !_viewModel.IsDataVaultConfigured &&
                !_viewModel.HasAuthenticatorPassword)
                throw new InvalidOperationException("Richte zuerst mindestens einen Tresor ein.");
            var addresses = LocalTransferAddresses.Find();
            if (addresses.Count == 0)
                throw new InvalidOperationException("Keine private LAN-Adresse gefunden. Verbinde beide Geräte mit demselben Netzwerk.");
            var selection = addresses.Count == 1 ? addresses[0].ToString() :
                await DisplayActionSheet("LAN-Adresse wählen", "Abbrechen", null,
                    addresses.Select(ip => ip.ToString()).ToArray());
            if (selection is null || !System.Net.IPAddress.TryParse(selection, out var address)) return;

            var wasPasswordLocked = !_viewModel.IsVaultUnlocked;
            var wasDataLocked = !_viewModel.IsDataVaultUnlocked;
            var wasAuthenticatorLocked = !_viewModel.IsAuthenticatorUnlocked;
            var phrase = AdaptiveDicewareTechnique.GenerateSessionPhrase();
            try
            {
                if (_viewModel.IsPasswordVaultConfigured && !await EnsureVaultUnlockedWithoutSyncAsync()) return;
                if (_viewModel.IsDataVaultConfigured && !await EnsureDataVaultUnlockedWithoutSyncAsync()) return;
                if (_viewModel.HasAuthenticatorPassword && !await EnsureAuthenticatorUnlockedAsync()) return;
                activity.Token.ThrowIfCancellationRequested();
                if (!_appLock.IsUnlocked) throw new OperationCanceledException();
                await ShowLoadingPageAsync("Verschlüssele Gesamtbackup …");
                try { backup = await Task.Run(() => _viewModel.CreateFullBackupAsync(phrase, activity.Token), activity.Token); }
                finally { await HideLoadingPageAsync(); }
            }
            finally
            {
                if (wasPasswordLocked && _viewModel.IsVaultUnlocked) _viewModel.LockVault();
                if (wasDataLocked && _viewModel.IsDataVaultUnlocked) _viewModel.LockDataVault();
                if (wasAuthenticatorLocked && _viewModel.IsAuthenticatorUnlocked) _viewModel.LockAuthenticator();
            }
            activity.Token.ThrowIfCancellationRequested();
            if (!_appLock.IsUnlocked) throw new OperationCanceledException();
            var page = new LocalSendPage(address, phrase, backup!, _localTransferActivity);
            await Navigation.PushModalAsync(page);
            backup = null; // The page owns and erases the encrypted backup.
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { await DisplayAlert("Lokaler Transfer", ex.Message, "OK"); }
        finally
        {
            if (backup is not null) CryptographicOperations.ZeroMemory(backup);
            _localTransferActivity.End(activity);
            _localTransferBusy = false;
        }
    }

    private async void OnLocalReceiveClicked(object? sender, EventArgs e)
    {
        if (_localTransferBusy) return;
        _localTransferBusy = true;
        LocalReceivedBackup? received = null;
        CancellationTokenSource? activity = null;
        try
        {
            if (!_appLock.IsUnlocked) throw new OperationCanceledException();
            await _viewModel.InitializeAsync();
            var page = new LocalReceivePage(_localTransferActivity);
            await Navigation.PushModalAsync(page);
            received = await page.WaitForResultAsync();
            if (received is null) return;
            activity = _localTransferActivity.Begin();
            activity.Token.ThrowIfCancellationRequested();
            if (!_appLock.IsUnlocked) throw new OperationCanceledException();

            LocalBackupContents contents;
            await ShowLoadingPageAsync("Prüfe Gesamtbackup …");
            try { contents = await Task.Run(() => LocalBackupVerifier.Verify(received.Bytes, received.Phrase), activity.Token); }
            finally { await HideLoadingPageAsync(); }
            activity.Token.ThrowIfCancellationRequested();
            if (!await DisplayAlert("Tresore empfangen", $"Enthalten: {contents.Description}. Mit lokalen Daten zusammenführen?",
                    "Weiter", "Abbrechen")) return;

            // Gather and confirm every missing local password before configuring a store.
            string? passwordMaster = contents.PasswordVault && !_viewModel.IsPasswordVaultConfigured
                ? await PromptNewLocalMasterAsync("Passwort-Tresor", activity.Token) : null;
            if (contents.PasswordVault && !_viewModel.IsPasswordVaultConfigured && passwordMaster is null) return;
            string? dataMaster = contents.DataVault && !_viewModel.IsDataVaultConfigured
                ? await PromptNewLocalMasterAsync("Datentresor", activity.Token) : null;
            if (contents.DataVault && !_viewModel.IsDataVaultConfigured && dataMaster is null) return;
            string? authenticatorMaster = contents.Authenticator && !_viewModel.HasAuthenticatorPassword
                ? await PromptNewLocalMasterAsync("Authenticator", activity.Token) : null;
            if (contents.Authenticator && !_viewModel.HasAuthenticatorPassword && authenticatorMaster is null) return;

            var wasPasswordLocked = !_viewModel.IsVaultUnlocked;
            var wasDataLocked = !_viewModel.IsDataVaultUnlocked;
            var wasAuthenticatorLocked = !_viewModel.IsAuthenticatorUnlocked;
            try
            {
                if (contents.PasswordVault && passwordMaster is null && !await EnsureVaultUnlockedWithoutSyncAsync()) return;
                if (contents.DataVault && dataMaster is null && !await EnsureDataVaultUnlockedWithoutSyncAsync()) return;
                if (contents.Authenticator && authenticatorMaster is null && !await EnsureAuthenticatorUnlockedAsync()) return;
                activity.Token.ThrowIfCancellationRequested();
                if (!_appLock.IsUnlocked) throw new OperationCanceledException();
                if (!await DisplayAlert("Import bestätigen", "Tresore jetzt zusammenführen?", "Importieren", "Abbrechen"))
                    return;
                activity.Token.ThrowIfCancellationRequested();
                if (!_appLock.IsUnlocked) throw new OperationCanceledException();

                await ShowLoadingPageAsync("Importiere Tresore …");
                try
                {
                    if (passwordMaster is not null)
                        await _passwordVault.SetMasterPasswordAsync(passwordMaster, false, activity.Token);
                    if (dataMaster is not null)
                        await _dataVault.SetMasterPasswordAsync(dataMaster, false, activity.Token);
                    if (authenticatorMaster is not null)
                        await _authenticator.SetupPasswordAsync(authenticatorMaster);
                    activity.Token.ThrowIfCancellationRequested();
                    using var stream = new MemoryStream(received.Bytes, writable: false);
                    if (!await _viewModel.RestoreFullBackupAsync(stream, received.Phrase,
                            cancellationToken: activity.Token))
                        throw new InvalidOperationException("Der Import wurde abgebrochen.");
                    await _viewModel.RefreshVaultStateAsync();
                    await _viewModel.RefreshDataVaultStateAsync();
                }
                finally { await HideLoadingPageAsync(); }
            }
            finally
            {
                if (wasPasswordLocked && _viewModel.IsVaultUnlocked) _viewModel.LockVault();
                if (wasDataLocked && _viewModel.IsDataVaultUnlocked) _viewModel.LockDataVault();
                if (wasAuthenticatorLocked && _viewModel.IsAuthenticatorUnlocked) _viewModel.LockAuthenticator();
            }
            activity.Token.ThrowIfCancellationRequested();
            if (!_appLock.IsUnlocked) throw new OperationCanceledException();
            await DisplayAlert("Lokaler Transfer", "Tresore wurden zusammengeführt.", "OK");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { await DisplayAlert("Lokaler Transfer fehlgeschlagen", ex.Message, "OK"); }
        finally
        {
            if (received is not null) CryptographicOperations.ZeroMemory(received.Bytes);
            if (activity is not null) _localTransferActivity.End(activity);
            _localTransferBusy = false;
        }
    }

    private async Task<string?> PromptNewLocalMasterAsync(string vault, CancellationToken token)
    {
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var first = await DisplayPasswordPromptAsync($"{vault} einrichten",
                "Neues lokales Master-Passwort:", "Weiter", "Abbrechen", showStrengthMeter: true);
            if (first is null) return null;
            try { NewPasswordPolicy.Validate(first, nameof(first)); }
            catch (ArgumentException ex) { await DisplayAlert(vault, ex.Message, "OK"); continue; }
            var repeated = await DisplayPasswordPromptAsync($"{vault} bestätigen",
                "Neues lokales Master-Passwort wiederholen:", "Bestätigen", "Abbrechen");
            if (repeated is null) return null;
            if (string.Equals(first, repeated, StringComparison.Ordinal)) return first;
            await DisplayAlert(vault, "Die Passwörter stimmen nicht überein.", "OK");
        }
    }

    private async Task ImportDataVaultEncryptedAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Export-Datei auswählen"
        });

        if (file is null)
        {
            return;
        }

        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib das Passwort der Export-Datei ein:",
            "Import",
            "Abbrechen");

        if (string.IsNullOrEmpty(filePassword))
        {
            return;
        }

        await using var stream = await file.OpenReadAsync();
        await _viewModel.ImportDataVaultWithFilePasswordAsync(stream, filePassword);
    }

    private async Task ExecuteSettingsActionAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            await DisplayAlert("Fehler", ex.Message, "OK");
        }
    }

    private async Task<string?> DisplayPasswordPromptAsync(string title, string message, string accept, string cancel,
        bool showStrengthMeter = false)
    {
        var navigation = Navigation ?? Microsoft.Maui.Controls.Application.Current?.MainPage?.Navigation;
        if (navigation is null)
        {
            throw new InvalidOperationException("Keine Navigationsinstanz verfügbar, um den Passwortdialog zu öffnen.");
        }

        var promptPage = new PasswordPromptPage(title, message, accept, cancel, showStrengthMeter);

        try
        {
            await navigation.PushModalAsync(promptPage);
            var result = await promptPage.WaitForResultAsync();

            if (navigation.ModalStack.Contains(promptPage))
            {
                await navigation.PopModalAsync();
            }

            return result;
        }
        catch
        {
            if (navigation.ModalStack.Contains(promptPage))
            {
                await navigation.PopModalAsync();
            }
            throw;
        }
    }

    private async Task ShowLoadingPageAsync(string message)
    {
        if (_loadingPage != null)
        {
            return;
        }

        var navigation = Navigation ?? Microsoft.Maui.Controls.Application.Current?.MainPage?.Navigation;
        if (navigation is null)
        {
            return;
        }

        _loadingPage = new LoadingPage(message);
        await navigation.PushModalAsync(_loadingPage);
    }

    private async Task HideLoadingPageAsync()
    {
        if (_loadingPage == null)
        {
            return;
        }

         var navigation = Navigation ?? Microsoft.Maui.Controls.Application.Current?.MainPage?.Navigation;
        if (navigation != null && navigation.ModalStack.Contains(_loadingPage))
        {
            await navigation.PopModalAsync();
        }

        _loadingPage = null;
    }

    private async void OnResetPasswordVaultClicked(object? sender, EventArgs e)
    {
        var popup = new ConfirmationPopup(
            "Passwort-Tresor zurücksetzen",
            "Möchtest du den Passwort-Tresor wirklich zurücksetzen? Alle gespeicherten Passwörter und das Master-Passwort werden unwiderruflich gelöscht. Diese Aktion kann nicht rückgängig gemacht werden.",
            "Zurücksetzen",
            "Abbrechen",
            confirmIsDestructive: true);

        var result = await this.ShowPopupAsync(popup);
        if (result is not bool confirm || !confirm)
        {
            return;
        }

        if (!await ConfirmResetIdentityAsync()) return;

        await ExecuteSettingsActionAsync(async () =>
        {
            await _viewModel.ResetPasswordVaultAsync();
            var successPopup = new SuccessPopup("Erfolg", "Der Passwort-Tresor wurde erfolgreich zurückgesetzt.", "OK");
            await this.ShowPopupAsync(successPopup);
        });
    }

    private async void OnResetDataVaultClicked(object? sender, EventArgs e)
    {
        var popup = new ConfirmationPopup(
            "Datentresor zurücksetzen",
            "Möchtest du den Datentresor wirklich zurücksetzen? Alle gespeicherten Daten und das Master-Passwort werden unwiderruflich gelöscht. Diese Aktion kann nicht rückgängig gemacht werden.",
            "Zurücksetzen",
            "Abbrechen",
            confirmIsDestructive: true);

        var result = await this.ShowPopupAsync(popup);
        if (result is not bool confirm || !confirm)
        {
            return;
        }

        if (!await ConfirmResetIdentityAsync()) return;

        await ExecuteSettingsActionAsync(async () =>
        {
            await _viewModel.ResetDataVaultAsync();
            var successPopup = new SuccessPopup("Erfolg", "Der Datentresor wurde erfolgreich zurückgesetzt.", "OK");
            await this.ShowPopupAsync(successPopup);
        });
    }

    private async void OnResetAuthenticatorClicked(object? sender, EventArgs e)
    {
        var popup = new ConfirmationPopup(
            "2FA-Tresor zurücksetzen",
            "Möchtest du den 2FA-Tresor wirklich zurücksetzen? Alle gespeicherten 2FA-Codes und das Authenticator-Passwort werden unwiderruflich gelöscht. Diese Aktion kann nicht rückgängig gemacht werden.",
            "Zurücksetzen",
            "Abbrechen",
            confirmIsDestructive: true);

        var result = await this.ShowPopupAsync(popup);
        if (result is not bool confirm || !confirm)
        {
            return;
        }

        if (!await ConfirmResetIdentityAsync()) return;

        await ExecuteSettingsActionAsync(async () =>
        {
            await _viewModel.ResetAuthenticatorAsync();
            var successPopup = new SuccessPopup("Erfolg", "Der 2FA-Tresor wurde erfolgreich zurückgesetzt.", "OK");
            await this.ShowPopupAsync(successPopup);
        });
    }

    private async Task<bool> ConfirmResetIdentityAsync()
    {
        var password = await DisplayPasswordPromptAsync(
            "App-Passwort bestätigen",
            "Gib dein App-Passwort ein, um den Tresor endgültig zurückzusetzen.",
            "Bestätigen",
            "Abbrechen");
        if (string.IsNullOrEmpty(password)) return false;
        if (await _viewModel.VerifyAppPasswordAsync(password)) return true;
        await DisplayAlert("Fehler", "Das App-Passwort ist falsch.", "OK");
        return false;
    }

    private async void OnSyncAccessModeToggled(object sender, ToggledEventArgs e)
    {
        await _viewModel.SetSyncAccessModeAsync(e.Value);
    }

    private async void OnManualSyncClicked(object sender, EventArgs e)
    {
        if (!_viewModel.IsSyncConfigured)
        {
             await DisplayAlert("Info", "Bitte richte die Synchronisation zuerst ein.", "OK");
             return;
        }

        // Capture initial states
        bool wasVaultLocked = !_viewModel.IsVaultUnlocked;
        bool wasDataVaultLocked = !_viewModel.IsDataVaultUnlocked;
        bool wasAuthenticatorLocked = !_viewModel.IsAuthenticatorUnlocked && _viewModel.HasAuthenticatorPassword;

        try
        {
            if (wasVaultLocked)
            {
                 bool unlocked = await EnsureVaultUnlockedAsync();
                 if (!unlocked) return;
            }

            if (wasDataVaultLocked)
            {
                 bool unlocked = await EnsureDataVaultUnlockedAsync();
                 if (!unlocked) return;
            }

            if (wasAuthenticatorLocked)
            {
                 bool unlocked = await EnsureAuthenticatorUnlockedAsync();
                 if (!unlocked) return;
            }

            // All ensured unlocked, proceed to sync
            await ShowLoadingPageAsync("Synchronisiere Tresore...");
            try
            {
                await _viewModel.SyncAllVaultsAsync();
            }
            catch (Exception ex)
            {
                 var fullError = ex.InnerException?.ToString() ?? ex.ToString();
                 if (fullError.Length > 800) fullError = fullError.Substring(0, 800) + "...";
                 await DisplayAlert("Fehler Details", fullError, "OK");
            }
            finally
            {
                await HideLoadingPageAsync();
            }
        }
        finally
        {
            // Always restore lock state, even if user cancelled locally
            if (wasVaultLocked && _viewModel.IsVaultUnlocked) _viewModel.LockVault();
            if (wasDataVaultLocked && _viewModel.IsDataVaultUnlocked) _viewModel.LockDataVault();
            if (wasAuthenticatorLocked && _viewModel.IsAuthenticatorUnlocked) _viewModel.LockAuthenticator();
        }
    }

    private async void OnLoadSyncClicked(object sender, EventArgs e)
    {
        if (!_viewModel.IsSyncConfigured)
        {
            await DisplayAlert("Info", "Bitte richte die Synchronisation zuerst ein.", "OK");
            return;
        }

        bool wasVaultLocked = !_viewModel.IsVaultUnlocked;
        bool wasDataVaultLocked = !_viewModel.IsDataVaultUnlocked;
        bool wasAuthenticatorLocked = !_viewModel.IsAuthenticatorUnlocked && _viewModel.HasAuthenticatorPassword;

        try
        {
            if (wasVaultLocked)
            {
                bool unlocked = await EnsureVaultUnlockedWithoutSyncAsync();
                if (!unlocked) return;
            }

            if (wasDataVaultLocked)
            {
                bool unlocked = await EnsureDataVaultUnlockedWithoutSyncAsync();
                if (!unlocked) return;
            }

            if (wasAuthenticatorLocked)
            {
                bool unlocked = await EnsureAuthenticatorUnlockedAsync();
                if (!unlocked) return;
            }

            await ShowLoadingPageAsync("Lade Tresore...");
            try
            {
                await _viewModel.LoadFromSyncAsync();
            }
            catch (Exception ex)
            {
                var fullError = ex.InnerException?.ToString() ?? ex.ToString();
                if (fullError.Length > 800) fullError = fullError.Substring(0, 800) + "...";
                await DisplayAlert("Fehler Details", fullError, "OK");
            }
            finally
            {
                await HideLoadingPageAsync();
            }
        }
        finally
        {
            if (wasVaultLocked && _viewModel.IsVaultUnlocked) _viewModel.LockVault();
            if (wasDataVaultLocked && _viewModel.IsDataVaultUnlocked) _viewModel.LockDataVault();
            if (wasAuthenticatorLocked && _viewModel.IsAuthenticatorUnlocked) _viewModel.LockAuthenticator();
        }
    }

    private async void OnRemoveSyncClicked(object sender, EventArgs e)
    {
        var popup = new ConfirmationPopup(
            "Sync-Verbindung entfernen",
            "Möchtest du die Sync-Verbindung wirklich löschen? Danach werden keine Daten mehr geladen oder hochgeladen.",
            "Entfernen",
            "Abbrechen",
            confirmIsDestructive: true);

        var result = await this.ShowPopupAsync(popup);
        if (result is not bool confirm || !confirm)
        {
            return;
        }

        try
        {
            await _viewModel.RemoveSyncConfigurationAsync();
        }
        catch (Exception ex)
        {
            var fullError = ex.InnerException?.ToString() ?? ex.ToString();
            if (fullError.Length > 800) fullError = fullError.Substring(0, 800) + "...";
            await DisplayAlert("Fehler Details", fullError, "OK");
        }
    }
}
