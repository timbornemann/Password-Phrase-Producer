using System;
using System.IO;
using System.Threading;
using CommunityToolkit.Maui.Storage;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.ViewModels;

namespace Password_Phrase_Producer.Views;

public partial class VaultPage : ContentPage
{
    private readonly VaultPageViewModel _viewModel;

    public VaultPage(VaultPageViewModel viewModel)
    {
        InitializeComponent();
        BindingContext = _viewModel = viewModel;
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

    private async void OnAddEntryClicked(object? sender, EventArgs e)
    {
        var entry = new PasswordVaultEntry();
        var result = await VaultEntryEditorPage.ShowAsync(Navigation, entry, "Neuer Tresor-Eintrag");
        if (result is null)
        {
            return;
        }

        await _viewModel.SaveEntryAsync(result);
    }

    private async void OnEditEntry(object? sender, EventArgs e)
    {
        if (sender is not SwipeItem swipeItem || swipeItem.CommandParameter is not PasswordVaultEntry entry)
        {
            return;
        }

        var editable = entry.Clone();
        var result = await VaultEntryEditorPage.ShowAsync(Navigation, editable, "Eintrag bearbeiten");
        if (result is null)
        {
            return;
        }

        await _viewModel.SaveEntryAsync(result);
    }

    private async void OnDeleteEntry(object? sender, EventArgs e)
    {
        if (sender is not SwipeItem swipeItem || swipeItem.CommandParameter is not PasswordVaultEntry entry)
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

    private async void OnSyncOptionsClicked(object? sender, EventArgs e)
    {
        var selection = await DisplayActionSheet("Tresor synchronisieren", "Abbrechen", null,
            "Backup exportieren",
            "Backup importieren",
            "Verschlüsselten Tresor exportieren",
            "Verschlüsselten Tresor importieren");

        try
        {
            switch (selection)
            {
                case "Backup exportieren":
                    await ExportBackupAsync();
                    break;
                case "Backup importieren":
                    await ImportBackupAsync();
                    break;
                case "Verschlüsselten Tresor exportieren":
                    await ExportEncryptedAsync();
                    break;
                case "Verschlüsselten Tresor importieren":
                    await ImportEncryptedAsync();
                    break;
            }
        }
        catch (Exception ex)
        {
            await DisplayAlert("Fehler", ex.Message, "OK");
        }
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
}
