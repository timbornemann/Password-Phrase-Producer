using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using CommunityToolkit.Maui.Views;
using CommunityToolkit.Maui.Storage;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.ApplicationModel.DataTransfer;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Storage;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Vault;
using Password_Phrase_Producer.ViewModels;
using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Views.Dialogs;

namespace Password_Phrase_Producer.Views;

public partial class VaultPage : ContentPage
{
    private readonly VaultPageViewModel _viewModel;
    private int _modalDepth;
    private PendingVaultEntryRequest? _pendingVaultRequest;
    private bool _isSubscribedToUnlockChanges;

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

        await HandlePendingVaultRequestAsync();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();

        if (_modalDepth > 0)
        {
            return;
        }

        _viewModel.Deactivate();
        DetachUnlockSubscription();
    }

    private async void OnAddEntryClicked(object? sender, EventArgs e)
    {
        if (!_viewModel.IsUnlocked)
        {
            await DisplayAlert("Tresor gesperrt", "Bitte entsperre den Tresor, bevor du neue Einträge hinzufügst.", "OK");
            return;
        }

        var entry = new PasswordVaultEntry();
        await ShowEditorAsync(entry, "Neuer Tresor-Eintrag");
    }

    private async Task HandlePendingVaultRequestAsync()
    {
        var request = VaultNavigationCoordinator.GetPendingRequest();
        if (request is null)
        {
            _pendingVaultRequest = null;
            DetachUnlockSubscription();
            return;
        }

        if (_viewModel.IsUnlocked)
        {
            await ProcessPendingVaultRequestAsync(request);
        }
        else
        {
            _pendingVaultRequest = request;
            AttachUnlockSubscription();
        }
    }

    private async Task ProcessPendingVaultRequestAsync(PendingVaultEntryRequest request)
    {
        if (!_viewModel.IsUnlocked)
        {
            return;
        }

        _pendingVaultRequest = null;
        VaultNavigationCoordinator.ClearPendingRequest(request.Id);
        DetachUnlockSubscription();

        var entry = new PasswordVaultEntry
        {
            Password = request.Password
        };

        await ShowEditorAsync(entry, "Passwort zum Tresor hinzufügen");
    }

    private void AttachUnlockSubscription()
    {
        if (_isSubscribedToUnlockChanges)
        {
            return;
        }

        _viewModel.PropertyChanged += OnViewModelPropertyChanged;
        _isSubscribedToUnlockChanges = true;
    }

    private void DetachUnlockSubscription()
    {
        if (!_isSubscribedToUnlockChanges)
        {
            return;
        }

        _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        _isSubscribedToUnlockChanges = false;
    }

    private async void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (!string.Equals(e.PropertyName, nameof(VaultPageViewModel.IsUnlocked), StringComparison.Ordinal))
        {
            return;
        }

        if (!_viewModel.IsUnlocked)
        {
            return;
        }

        var request = _pendingVaultRequest ?? VaultNavigationCoordinator.GetPendingRequest();
        if (request is null)
        {
            DetachUnlockSubscription();
            return;
        }

        await ProcessPendingVaultRequestAsync(request);
    }

    private async void OnShowDetailTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not PasswordVaultEntry entry)
        {
            return;
        }

        BeginModalInteraction();
        try
        {
            var editRequested = await VaultEntryDetailPage.ShowAsync(Navigation, entry);
            if (editRequested)
            {
                var editable = entry.Clone();
                await ShowEditorAsync(editable, "Eintrag bearbeiten");
            }
        }
        finally
        {
            EndModalInteraction();
        }
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

        var popup = new ConfirmationPopup("Eintrag löschen", $"Soll der Eintrag '{entry.Label}' gelöscht werden?", "Löschen", "Abbrechen", true);
        var result = await this.ShowPopupAsync(popup);
        if (result is not bool confirm || !confirm)
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
            PasswordVaultEntry? result;
            try
            {
                result = await VaultEntryEditorPage.ShowAsync(Navigation, entry, title, _viewModel.AvailableCategories);
            }
            catch (InvalidOperationException ex)
            {
                Debug.WriteLine($"[VaultPage] Editor konnte nicht geöffnet werden: {ex}");

                var message = BuildEditorErrorMessage("Der Editor konnte nicht geöffnet werden.", ex);
                await DisplayAlert("Editor nicht verfügbar", message, "OK");
                return;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[VaultPage] Unerwarteter Fehler beim Öffnen des Editors: {ex}");

                var message = BuildEditorErrorMessage("Beim Öffnen des Editors ist ein unerwarteter Fehler aufgetreten.", ex);
                await DisplayAlert("Fehler", message, "OK");
                return;
            }

            if (result is null)
            {
                return;
            }

            try
            {
                await _viewModel.SaveEntryAsync(result);
            }
            catch (Exception ex)
            {
                await DisplayAlert("Fehler", $"Der Eintrag konnte nicht gespeichert werden: {ex.Message}", "OK");
            }
        }
        finally
        {
            EndModalInteraction();
        }
    }

    private static string BuildEditorErrorMessage(string headline, Exception exception)
    {
        var builder = new StringBuilder();
        builder.AppendLine(headline);
        builder.AppendLine();
        builder.Append("Fehlertyp: ")
            .AppendLine(exception.GetType().FullName);
        builder.Append("Fehlermeldung: ")
            .AppendLine(exception.Message);

        if (exception.InnerException is not null)
        {
            builder.AppendLine()
                .AppendLine("Innere Ausnahme:")
                .AppendLine(exception.InnerException.ToString());
        }

        if (exception.Data is { Count: > 0 } && exception.Data.Contains("NavigationDiagnostics"))
        {
            if (exception.Data["NavigationDiagnostics"] is string diagnostics && !string.IsNullOrWhiteSpace(diagnostics))
            {
                builder.AppendLine()
                    .AppendLine("Navigationsdiagnose:")
                    .AppendLine(diagnostics);
            }
        }

        if (!string.IsNullOrWhiteSpace(exception.StackTrace))
        {
            builder.AppendLine()
                .AppendLine("Stacktrace:")
                .AppendLine(TrimStackTrace(exception.StackTrace));
        }

        return builder.ToString();
    }

    private static string TrimStackTrace(string? stackTrace)
    {
        if (string.IsNullOrWhiteSpace(stackTrace))
        {
            return string.Empty;
        }

        var lines = stackTrace.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        const int maxLines = 12;

        if (lines.Length <= maxLines)
        {
            return string.Join(Environment.NewLine, lines);
        }

        var trimmed = lines.Take(maxLines).ToList();
        trimmed.Add("…");
        return string.Join(Environment.NewLine, trimmed);
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

        // Visual feedback - find the Border element
        Border? border = null;
        if (sender is TapGestureRecognizer tapRecognizer && tapRecognizer.Parent is Border b)
        {
            border = b;
        }
        else if (sender is Border borderDirect)
        {
            border = borderDirect;
        }

        if (border is not null)
        {
            await AnimateCopyButton(border);
        }

        await Clipboard.Default.SetTextAsync(entry.Password);
        await ToastService.ShowCopiedAsync("Passwort");
    }

    private async void OnCopyUsernameTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not PasswordVaultEntry entry)
        {
            return;
        }

        if (string.IsNullOrEmpty(entry.Username))
        {
            return;
        }

        // Visual feedback - find the Border element
        Border? border = null;
        if (sender is TapGestureRecognizer tapRecognizer && tapRecognizer.Parent is Border b)
        {
            border = b;
        }
        else if (sender is Border borderDirect)
        {
            border = borderDirect;
        }

        if (border is not null)
        {
            await AnimateCopyButton(border);
        }

        await Clipboard.Default.SetTextAsync(entry.Username);
        await ToastService.ShowCopiedAsync("Benutzername");
    }

    private static async Task AnimateCopyButton(Border border)
    {
        var originalColor = border.BackgroundColor ?? Microsoft.Maui.Graphics.Color.FromArgb("#2A2F4A");
        var highlightColor = Microsoft.Maui.Graphics.Color.FromArgb("#4A5CFF");

        // Cancel any existing animations
        border.AbortAnimation("CopyButtonAnimation1");
        border.AbortAnimation("CopyButtonAnimation2");

        // Animate to highlight color
        var animation1 = new Animation(
            value => border.BackgroundColor = LerpColor(originalColor, highlightColor, value),
            0, 1, Easing.CubicOut);
        animation1.Commit(border, "CopyButtonAnimation1", 16, 150, Easing.CubicOut, (v, c) =>
        {
            // Ensure we're at highlight color when animation completes
            border.BackgroundColor = highlightColor;
        });

        await Task.Delay(150);

        // Animate back to original color
        var animation2 = new Animation(
            value => border.BackgroundColor = LerpColor(highlightColor, originalColor, value),
            0, 1, Easing.CubicIn);
        animation2.Commit(border, "CopyButtonAnimation2", 16, 200, Easing.CubicIn, (v, c) =>
        {
            // Ensure we're back to original color when animation completes
            border.BackgroundColor = originalColor;
        });

        await Task.Delay(200);
        
        // Final safety check - ensure original color is set
        border.BackgroundColor = originalColor;
    }

    private static Microsoft.Maui.Graphics.Color LerpColor(
        Microsoft.Maui.Graphics.Color from,
        Microsoft.Maui.Graphics.Color to,
        double t)
    {
        var r = (int)(from.Red + (to.Red - from.Red) * t);
        var g = (int)(from.Green + (to.Green - from.Green) * t);
        var b = (int)(from.Blue + (to.Blue - from.Blue) * t);
        var a = (int)(from.Alpha + (to.Alpha - from.Alpha) * t);
        return Microsoft.Maui.Graphics.Color.FromRgba(r, g, b, a);
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

    private async void OnSettingsTapped(object? sender, TappedEventArgs e)
        => await NavigateToSettingsAsync();

    private async void OnSettingsButtonClicked(object? sender, EventArgs e)
        => await NavigateToSettingsAsync();

    private static async Task NavigateToSettingsAsync()
    {
        if (Shell.Current is null)
        {
            return;
        }

        await Shell.Current.GoToAsync("//settings");
    }

    private async void OnCategoryFilterTapped(object? sender, TappedEventArgs e)
    {
        if (_viewModel.CategoryFilterOptions.Count == 0)
        {
            return;
        }

        var options = new List<ActionSheetPopupOption>();
        foreach (var category in _viewModel.CategoryFilterOptions)
        {
            var isSelected = string.Equals(category, _viewModel.SelectedCategory, StringComparison.CurrentCultureIgnoreCase);
            options.Add(new ActionSheetPopupOption(category, category, IsSelected: isSelected));
        }

        var popup = new ActionSheetPopup("Kategorie wählen", options, cancelText: "Abbrechen");
        var selection = await this.ShowPopupAsync(popup) as string;

        if (string.IsNullOrWhiteSpace(selection) || string.Equals(selection, _viewModel.SelectedCategory, StringComparison.CurrentCultureIgnoreCase))
        {
            return;
        }

        foreach (var category in _viewModel.CategoryFilterOptions)
        {
            if (string.Equals(category, selection, StringComparison.CurrentCultureIgnoreCase))
            {
                _viewModel.SelectedCategory = category;
                break;
            }
        }
    }

    private async void OnExportBackupClicked(object? sender, EventArgs e)
        => await ExecuteVaultActionAsync(ExportBackupAsync);

    private async void OnImportBackupClicked(object? sender, EventArgs e)
        => await ExecuteVaultActionAsync(async () =>
        {
            await ImportBackupAsync();
            await _viewModel.EnsureAccessStateAsync();
        });

    private async void OnExportEncryptedClicked(object? sender, EventArgs e)
        => await ExecuteVaultActionAsync(ExportEncryptedAsync);

    private async void OnImportEncryptedClicked(object? sender, EventArgs e)
        => await ExecuteVaultActionAsync(ImportEncryptedAsync);

    private async void OnChangePasswordMenuItemClicked(object? sender, EventArgs e)
    {
        if (!_viewModel.IsUnlocked)
        {
            await DisplayAlert("Tresor gesperrt", "Bitte entsperre den Tresor, bevor du das Master-Passwort ändern kannst.", "OK");
            return;
        }

        await ExecuteVaultActionAsync(ChangeMasterPasswordAsync);
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
        var navigation = Navigation ?? Microsoft.Maui.Controls.Application.Current?.MainPage?.Navigation;
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

    private async Task ExecuteVaultActionAsync(Func<Task> action)
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
}
