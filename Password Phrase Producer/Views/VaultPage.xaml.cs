using System;
using System.IO;
using System.Linq;
using System.Threading;
using CommunityToolkit.Maui.Storage;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Microsoft.Maui.ApplicationModel.DataTransfer;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.ViewModels;
using Password_Phrase_Producer.Views.Dialogs;

namespace Password_Phrase_Producer.Views;

public partial class VaultPage : ContentPage
{
    private readonly VaultPageViewModel _viewModel;
    private int _modalDepth;

    public VaultPage(VaultPageViewModel viewModel)
    {
        InitializeComponent();
        BindingContext = _viewModel = viewModel;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();

        if (_modalDepth > 0)
        {
            return;
        }

        _viewModel.Activate();
        await _viewModel.InitializeAsync();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();

        if (_modalDepth > 0)
        {
            return;
        }

        _viewModel.Deactivate();
    }

    private async void OnAddEntryClicked(object? sender, TappedEventArgs e)
    {
        var entry = new PasswordVaultEntry();
        await ShowEditorAsync(entry, "Neuer Tresor-Eintrag");
    }

    private async void OnEditEntryTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not PasswordVaultEntry entry)
        {
            return;
        }

        var editable = entry.Clone();
        await ShowEditorAsync(editable, "Eintrag bearbeiten");
    }

    private async void OnDeleteEntryTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not PasswordVaultEntry entry)
        {
            return;
        }

        var confirm = await DisplayAlert("Eintrag löschen", $"Soll der Eintrag '{entry.Label}' gelöscht werden?", "Löschen", "Abbrechen");
        if (!confirm)
        {
            return;
        }

        await _viewModel.DeleteEntryAsync(entry);
    }

    private async void OnOpenUrl(object? sender, TappedEventArgs e)
    {
        var url = e.Parameter as string;
        if (string.IsNullOrWhiteSpace(url))
        {
            return;
        }

        url = url.Trim();
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            url = $"https://{url}";
        }

        try
        {
            await Launcher.OpenAsync(url);
        }
        catch (Exception ex)
        {
            await DisplayAlert("Fehler", $"Die URL konnte nicht geöffnet werden: {ex.Message}", "OK");
        }
    }

    private async void OnSyncOptionsClicked(object? sender, TappedEventArgs e)
    {
        var selection = await DisplayActionSheet("Tresor synchronisieren", "Abbrechen", null,
            "Backup exportieren",
            "Backup importieren",
            "Verschlüsselten Tresor exportieren",
            "Verschlüsselten Tresor importieren",
            "Master-Passwort ändern");

        try
        {
            switch (selection)
            {
                case "Backup exportieren":
                    await ExportBackupAsync();
                    break;
                case "Backup importieren":
                    await ImportBackupAsync();
                    await _viewModel.EnsureAccessStateAsync();
                    break;
                case "Verschlüsselten Tresor exportieren":
                    await ExportEncryptedAsync();
                    break;
                case "Verschlüsselten Tresor importieren":
                    await ImportEncryptedAsync();
                    break;
                case "Master-Passwort ändern":
                    await ChangeMasterPasswordAsync();
                    break;
            }
        }
        catch (Exception ex)
        {
            await DisplayAlert("Fehler", ex.Message, "OK");
        }
    }

    private async void OnBackTapped(object? sender, TappedEventArgs e)
    {
        if (Shell.Current is not null)
        {
            await Shell.Current.GoToAsync("//home");
        }
    }

    private async Task ShowEditorAsync(PasswordVaultEntry entry, string title)
    {
        BeginModalInteraction();
        try
        {
            var result = await VaultEntryEditorPage.ShowAsync(Navigation, entry, title, _viewModel.AvailableCategories);
            if (result is null)
            {
                return;
            }

            await _viewModel.SaveEntryAsync(result);
        }
        finally
        {
            EndModalInteraction();
        }
    }

    private async void OnCopyPasswordTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not PasswordVaultEntry entry)
        {
            return;
        }

        if (string.IsNullOrEmpty(entry.Password))
        {
            return;
        }

        await Clipboard.Default.SetTextAsync(entry.Password);
        await DisplayAlert("Kopiert", "Das Passwort wurde in die Zwischenablage kopiert.", "OK");
    }

    private void OnTogglePasswordVisibilityTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not PasswordVaultEntry entry)
        {
            return;
        }

        entry.IsPasswordVisible = !entry.IsPasswordVisible;
    }

    private void OnOpenMenuTapped(object? sender, TappedEventArgs e)
    {
        if (Shell.Current is not null)
        {
            Shell.Current.FlyoutIsPresented = true;
        }
    }

    private async void OnChangePasswordTapped(object? sender, TappedEventArgs e)
    {
        if (!_viewModel.IsUnlocked)
        {
            await DisplayAlert("Tresor gesperrt", "Bitte entsperre den Tresor, bevor du das Master-Passwort ändern kannst.", "OK");
            return;
        }

        await ChangeMasterPasswordAsync();
    }

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

        await using var stream = await file.OpenReadAsync();
        await _viewModel.RestoreBackupAsync(stream);
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
            PickerTitle = "Verschlüsselte Tresordatei auswählen"
        });

        if (file is null)
        {
            return;
        }

        await using var stream = await file.OpenReadAsync();
        await _viewModel.ImportEncryptedVaultAsync(stream);
    }

    private async Task ChangeMasterPasswordAsync()
    {
        var newPassword = await DisplayPasswordPromptAsync(
            "Master-Passwort ändern",
            "Bitte gib das neue Master-Passwort ein.",
            "Weiter",
            "Abbrechen");

        if (newPassword is null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(newPassword))
        {
            await DisplayAlert("Fehler", "Das Master-Passwort darf nicht leer sein.", "OK");
            return;
        }

        var confirmPassword = await DisplayPasswordPromptAsync(
            "Master-Passwort bestätigen",
            "Bitte gib das neue Master-Passwort erneut ein.",
            "Ändern",
            "Abbrechen");

        if (confirmPassword is null)
        {
            return;
        }

        if (!string.Equals(newPassword, confirmPassword, StringComparison.Ordinal))
        {
            await DisplayAlert("Fehler", "Die Passwörter stimmen nicht überein.", "OK");
            return;
        }

        bool enableBiometric = _viewModel.EnableBiometric;
        if (_viewModel.CanUseBiometric)
        {
            enableBiometric = await DisplayAlert(
                "Biometrische Anmeldung",
                "Soll die biometrische Anmeldung weiterhin verfügbar sein?",
                "Ja",
                "Nein");
        }

        try
        {
            await _viewModel.ChangeMasterPasswordAsync(newPassword, enableBiometric);
            await DisplayAlert("Erfolg", "Das Master-Passwort wurde aktualisiert.", "OK");
        }
        catch (Exception ex)
        {
            await DisplayAlert("Fehler", $"Das Master-Passwort konnte nicht geändert werden: {ex.Message}", "OK");
        }
    }

    private async Task<string?> DisplayPasswordPromptAsync(string title, string message, string accept, string cancel)
    {
        var navigation = Navigation ?? Application.Current?.MainPage?.Navigation;
        if (navigation is null)
        {
            throw new InvalidOperationException("Keine Navigationsinstanz verfügbar, um den Passwortdialog zu öffnen.");
        }

        var promptPage = new PasswordPromptPage(title, message, accept, cancel);

        BeginModalInteraction();
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
        finally
        {
            EndModalInteraction();
        }
    }

    private void BeginModalInteraction()
        => _modalDepth++;

    private void EndModalInteraction()
    {
        if (_modalDepth > 0)
        {
            _modalDepth--;
        }
    }
}
