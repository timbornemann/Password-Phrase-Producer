using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Maui.Storage;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.ViewModels;
using Password_Phrase_Producer.Views.Dialogs;

namespace Password_Phrase_Producer.Views;

public partial class SettingsPage : ContentPage
{
    private readonly VaultSettingsViewModel _viewModel;

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

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        _viewModel.Activate();
        await _viewModel.InitializeAsync();
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
        => await ExecuteSettingsActionAsync(async () =>
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

    private async void OnImportFullBackupClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
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
            }
            finally
            {
                // Lock all vaults after import
                _viewModel.LockAllVaults();
            }
        });

    private async void OnExportBackupClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            if (!await EnsureVaultUnlockedAsync())
            {
                return;
            }

            try
            {
                await ExportBackupAsync();
            }
            finally
            {
                _viewModel.LockVault();
            }
        });

    private async void OnImportBackupClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            await ImportBackupAsync();
            await _viewModel.RefreshVaultStateAsync();
        });

    private async void OnExportDataVaultBackupClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            if (!await EnsureDataVaultUnlockedAsync())
            {
                return;
            }

            try
            {
                await ExportDataVaultBackupAsync();
            }
            finally
            {
                _viewModel.LockDataVault();
            }
        });

    private async void OnImportDataVaultBackupClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            await ImportDataVaultBackupAsync();
            await _viewModel.RefreshDataVaultStateAsync();
        });

    private async void OnExportEncryptedClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            if (!await EnsureVaultUnlockedAsync())
            {
                return;
            }

            try
            {
                await ExportEncryptedAsync();
            }
            finally
            {
                _viewModel.LockVault();
            }
        });

    private async void OnImportEncryptedClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            await ImportEncryptedAsync();
            await _viewModel.RefreshVaultStateAsync();
        });

    private async void OnExportDataVaultEncryptedClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            if (!await EnsureDataVaultUnlockedAsync())
            {
                return;
            }

            try
            {
                await ExportDataVaultEncryptedAsync();
            }
            finally
            {
                _viewModel.LockDataVault();
            }
        });

    private async void OnExportAuthenticatorClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            if (!await EnsureAuthenticatorUnlockedAsync())
            {
                return;
            }

            try
            {
                await ExportAuthenticatorAsync();
            }
            finally
            {
                _viewModel.LockAuthenticator();
            }
        });

    private async void OnImportAuthenticatorClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            if (!await EnsureAuthenticatorUnlockedAsync())
            {
                return;
            }

            try
            {
                await ImportAuthenticatorAsync();
            }
            finally
            {
                _viewModel.LockAuthenticator();
            }
        });

    private async void OnImportDataVaultEncryptedClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            await ImportDataVaultEncryptedAsync();
            await _viewModel.RefreshDataVaultStateAsync();
        });

    private async Task ExportBackupAsync()
    {
        var backupBytes = await _viewModel.CreateBackupAsync();
        await using var stream = new MemoryStream(backupBytes);
        var result = await FileSaver.Default.SaveAsync("vault-backup.json", stream, CancellationToken.None);
        if (!result.IsSuccessful && result.Exception is not null)
        {
            throw new InvalidOperationException(result.Exception.Message, result.Exception);
        }
    }

    private async Task ImportBackupAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Backup auswählen"
        });

        if (file is null)
        {
            return;
        }

        var useMerge = await AskMergeOrReplaceAsync();
        if (useMerge is null)
        {
            return; // Cancelled
        }

        await using var stream = await file.OpenReadAsync();
        if (useMerge == true)
        {
            await _viewModel.RestoreBackupWithMergeAsync(stream);
        }
        else
        {
            await _viewModel.RestoreBackupAsync(stream);
        }
    }

    private async Task ExportDataVaultBackupAsync()
    {
        var backupBytes = await _viewModel.CreateDataVaultBackupAsync();
        await using var stream = new MemoryStream(backupBytes);
        var result = await FileSaver.Default.SaveAsync("datentresor-backup.json", stream, CancellationToken.None);
        if (!result.IsSuccessful && result.Exception is not null)
        {
            throw new InvalidOperationException(result.Exception.Message, result.Exception);
        }
    }

    private async Task ImportDataVaultBackupAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Datentresor-Backup auswählen"
        });

        if (file is null)
        {
            return;
        }

        var useMerge = await AskMergeOrReplaceAsync();
        if (useMerge is null)
        {
            return; // Cancelled
        }

        await using var stream = await file.OpenReadAsync();
        if (useMerge == true)
        {
            await _viewModel.RestoreDataVaultBackupWithMergeAsync(stream);
        }
        else
        {
            await _viewModel.RestoreDataVaultBackupAsync(stream);
        }
    }

    private async Task ExportEncryptedAsync()
    {
        var bytes = await _viewModel.ExportEncryptedVaultAsync();
        await using var stream = new MemoryStream(bytes);
        var result = await FileSaver.Default.SaveAsync("vault.json.enc", stream, CancellationToken.None);
        if (!result.IsSuccessful && result.Exception is not null)
        {
            throw new InvalidOperationException(result.Exception.Message, result.Exception);
        }
    }

    private async Task ImportEncryptedAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Verschlüsselte Passwort Tresordatei auswählen"
        });

        if (file is null)
        {
            return;
        }

        await using var stream = await file.OpenReadAsync();
        await _viewModel.ImportEncryptedVaultAsync(stream);
    }

    private async Task ExportDataVaultEncryptedAsync()
    {
        var bytes = await _viewModel.ExportEncryptedDataVaultAsync();
        await using var stream = new MemoryStream(bytes);
        var result = await FileSaver.Default.SaveAsync("data-vault.json.enc", stream, CancellationToken.None);
        if (!result.IsSuccessful && result.Exception is not null)
        {
            throw new InvalidOperationException(result.Exception.Message, result.Exception);
        }
    }

    private async Task ExportAuthenticatorAsync()
    {
        var bytes = await _viewModel.CreateAuthenticatorBackupAsync();
        await using var stream = new MemoryStream(bytes);
        var result = await FileSaver.Default.SaveAsync("authenticator-backup.json", stream, CancellationToken.None);
        if (!result.IsSuccessful && result.Exception is not null)
        {
            throw new InvalidOperationException(result.Exception.Message, result.Exception);
        }
    }

    private async Task ImportAuthenticatorAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Authenticator-Backup auswählen"
        });

        if (file is null)
        {
            return;
        }

        var useMerge = await AskMergeOrReplaceAsync();
        if (useMerge is null)
        {
            return; // Cancelled
        }

        await using var stream = await file.OpenReadAsync();
        if (useMerge == true)
        {
            await _viewModel.RestoreAuthenticatorBackupWithMergeAsync(stream);
        }
        else
        {
            await _viewModel.RestoreAuthenticatorBackupAsync(stream);
        }
    }

    private async Task ExportFullBackupAsync()
    {
        var bytes = await _viewModel.CreateFullBackupAsync();
        await using var stream = new MemoryStream(bytes);
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HHmmss");
        var result = await FileSaver.Default.SaveAsync($"full-backup-{timestamp}.json", stream, CancellationToken.None);
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

        var useMerge = await AskMergeOrReplaceAsync();
        if (useMerge is null)
        {
            return; // Cancelled
        }

        await using var stream = await file.OpenReadAsync();
        await _viewModel.RestoreFullBackupAsync(stream, useMerge == true);
    }

    private async Task ImportDataVaultEncryptedAsync()
    {
        var file = await FilePicker.Default.PickAsync(new PickOptions
        {
            PickerTitle = "Verschlüsselte Datentresordatei auswählen"
        });

        if (file is null)
        {
            return;
        }

        await using var stream = await file.OpenReadAsync();
        await _viewModel.ImportEncryptedDataVaultAsync(stream);
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
}
