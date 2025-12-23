using System;
using System.Threading.Tasks;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.ApplicationModel.DataTransfer;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services;

namespace Password_Phrase_Producer.Views;

public partial class VaultEntryDetailPage : ContentPage
{
    private readonly TaskCompletionSource<bool> _resultSource = new();
    private readonly PasswordVaultEntry _entry;
    private bool _isPasswordVisible = true;

    public bool HasNotes => !string.IsNullOrWhiteSpace(_entry.Notes) || !string.IsNullOrWhiteSpace(_entry.FreeText);

    public bool EditRequested { get; private set; }

    public VaultEntryDetailPage(PasswordVaultEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _entry = entry;
        InitializeComponent();
        BindingContext = entry;
    }

    public static async Task<bool> ShowAsync(INavigation navigation, PasswordVaultEntry entry)
    {
        ArgumentNullException.ThrowIfNull(navigation);
        ArgumentNullException.ThrowIfNull(entry);

        var page = new VaultEntryDetailPage(entry);
        await navigation.PushModalAsync(page);

        await page._resultSource.Task;

        if (navigation.ModalStack.Contains(page))
        {
            await navigation.PopModalAsync();
        }

        return page.EditRequested;
    }

    private void OnCloseTapped(object? sender, TappedEventArgs e)
    {
        _resultSource.TrySetResult(false);
    }

    private void OnCloseClicked(object? sender, EventArgs e)
    {
        _resultSource.TrySetResult(false);
    }

    private void OnEditTapped(object? sender, TappedEventArgs e)
    {
        EditRequested = true;
        _resultSource.TrySetResult(true);
    }

    private void OnTogglePasswordTapped(object? sender, TappedEventArgs e)
    {
        _isPasswordVisible = !_isPasswordVisible;

        if (_isPasswordVisible)
        {
            PasswordLabel.Text = _entry.Password;
            TogglePasswordIcon.Source = "eye.png";
        }
        else
        {
            PasswordLabel.Text = new string('•', Math.Min(_entry.Password?.Length ?? 0, 20));
            TogglePasswordIcon.Source = "eyeoff.png";
        }
    }

    private async void OnCopyUsernameTapped(object? sender, TappedEventArgs e)
    {
        if (string.IsNullOrEmpty(_entry.Username))
        {
            return;
        }

        await Clipboard.Default.SetTextAsync(_entry.Username);
        await ToastService.ShowCopiedAsync("Benutzername");
    }

    private async void OnCopyPasswordTapped(object? sender, TappedEventArgs e)
    {
        if (string.IsNullOrEmpty(_entry.Password))
        {
            return;
        }

        await Clipboard.Default.SetTextAsync(_entry.Password);
        await ToastService.ShowCopiedAsync("Passwort");
    }

    private async void OnOpenUrlTapped(object? sender, TappedEventArgs e)
    {
        var url = _entry.Url;
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

    protected override bool OnBackButtonPressed()
    {
        _resultSource.TrySetResult(false);
        return true;
    }
}

