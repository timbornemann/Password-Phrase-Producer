using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Maui.Storage;
using CommunityToolkit.Maui.Views;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.ViewModels;
using Password_Phrase_Producer.Views.Dialogs;

namespace Password_Phrase_Producer.Views;

public partial class SettingsPage : ContentPage
{
    private readonly VaultSettingsViewModel _viewModel;
    private LoadingPage? _loadingPage;

    public SettingsPage(VaultSettingsViewModel viewModel)
    {
        InitializeComponent();
        BindingContext = _viewModel = viewModel;
    }

    private async Task<bool> EnsureVaultUnlockedAsync()
    {
        if (_viewModel.IsVaultUnlocked)
        {
            return true;
        }

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
            await DisplayAlert("Fehler", "Falsches Passwort.", "OK");
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
            await DisplayAlert("Fehler", "Falsches Passwort.", "OK");
            return false;
        }

        await _viewModel.RefreshVaultStateAsync();
        return true;
    }

    private async Task<bool> EnsureDataVaultUnlockedAsync()
    {
        if (_viewModel.IsDataVaultUnlocked)
        {
            return true;
        }

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
            await DisplayAlert("Fehler", "Falsches Passwort.", "OK");
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
            await DisplayAlert("Fehler", "Falsches Passwort.", "OK");
            return false;
        }

        await _viewModel.RefreshDataVaultStateAsync();
        return true;
    }

    private async Task<bool> EnsureAuthenticatorUnlockedAsync()
    {
        if (!_viewModel.HasAuthenticatorPassword)
        {
            return true; // No password set, consider it unlocked
        }

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
            await DisplayAlert("Fehler", "Falsches Passwort.", "OK");
            return false;
        }

        return true;
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
                    await ImportFullBackupAsync();
                    await _viewModel.RefreshVaultStateAsync();
                    await _viewModel.RefreshDataVaultStateAsync();
                    success = true;
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
            "Abbrechen");

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
            "Abbrechen");

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
            "Abbrechen");

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
            "Abbrechen");

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
            "Abbrechen");

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

    private async Task ImportFullBackupAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Gesamtbackup auswählen"
        });

        if (file is null)
        {
            return;
        }

        var filePassword = await DisplayPasswordPromptAsync(
            "Export-Passwort",
            "Gib das Passwort des Gesamtbackups ein:",
            "Import",
            "Abbrechen");

        if (string.IsNullOrEmpty(filePassword))
        {
            return;
        }

        await using var stream = await file.OpenReadAsync();
        await _viewModel.RestoreFullBackupAsync(stream, filePassword);
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

    private async Task<string?> DisplayPasswordPromptAsync(string title, string message, string accept, string cancel)
    {
        var navigation = Navigation ?? Microsoft.Maui.Controls.Application.Current?.MainPage?.Navigation;
        if (navigation is null)
        {
            throw new InvalidOperationException("Keine Navigationsinstanz verfügbar, um den Passwortdialog zu öffnen.");
        }

        var promptPage = new PasswordPromptPage(title, message, accept, cancel);

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

        await ExecuteSettingsActionAsync(async () =>
        {
            await _viewModel.ResetAuthenticatorAsync();
            var successPopup = new SuccessPopup("Erfolg", "Der 2FA-Tresor wurde erfolgreich zurückgesetzt.", "OK");
            await this.ShowPopupAsync(successPopup);
        });
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
