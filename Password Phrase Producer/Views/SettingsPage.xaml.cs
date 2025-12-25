using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Maui.Storage;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.ViewModels;

namespace Password_Phrase_Producer.Views;

public partial class SettingsPage : ContentPage
{
    private readonly VaultSettingsViewModel _viewModel;

    public SettingsPage(VaultSettingsViewModel viewModel)
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

    private async void OnExportBackupClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(ExportBackupAsync);

    private async void OnImportBackupClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            await ImportBackupAsync();
            await _viewModel.RefreshVaultStateAsync();
        });

    private async void OnExportDataVaultBackupClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(ExportDataVaultBackupAsync);

    private async void OnImportDataVaultBackupClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            await ImportDataVaultBackupAsync();
            await _viewModel.RefreshDataVaultStateAsync();
        });

    private async void OnExportEncryptedClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(ExportEncryptedAsync);

    private async void OnImportEncryptedClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(async () =>
        {
            await ImportEncryptedAsync();
            await _viewModel.RefreshVaultStateAsync();
        });

    private async void OnExportDataVaultEncryptedClicked(object? sender, EventArgs e)
        => await ExecuteSettingsActionAsync(ExportDataVaultEncryptedAsync);

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

        await using var stream = await file.OpenReadAsync();
        await _viewModel.RestoreBackupAsync(stream);
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

        await using var stream = await file.OpenReadAsync();
        await _viewModel.RestoreDataVaultBackupAsync(stream);
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
