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

        await Clipboard.Default.SetTextAsync(_entry.Username);
        await ToastService.ShowCopiedAsync("Benutzername");
    }

    private async void OnCopyPasswordTapped(object? sender, TappedEventArgs e)
    {
        if (string.IsNullOrEmpty(_entry.Password))
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

        await Clipboard.Default.SetTextAsync(_entry.Password);
        await ToastService.ShowCopiedAsync("Passwort");
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
        var r = from.Red + (to.Red - from.Red) * t;
        var g = from.Green + (to.Green - from.Green) * t;
        var b = from.Blue + (to.Blue - from.Blue) * t;
        var a = from.Alpha + (to.Alpha - from.Alpha) * t;
        return Microsoft.Maui.Graphics.Color.FromRgba(r, g, b, a);
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

