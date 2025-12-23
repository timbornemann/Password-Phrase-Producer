using System;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Graphics;
using Password_Phrase_Producer.Views;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public abstract class PasswordGeneratorContentView : ContentView, IPasswordResultProvider, IPasswordGeneratorActionHost
{
    private string? _lastGeneratedPassword;
    private ContentView? _addToVaultHost;

    public event EventHandler<string>? PasswordGenerated;

    public event EventHandler? PasswordCleared;

    public string? LastGeneratedPassword
    {
        get => _lastGeneratedPassword;
        private set => _lastGeneratedPassword = value;
    }

    protected void RegisterAddToVaultHost(ContentView host)
    {
        _addToVaultHost = host;
        _addToVaultHost.IsVisible = false;
    }

    bool IPasswordGeneratorActionHost.TrySetAddToVaultAction(View actionView)
    {
        if (_addToVaultHost is null)
        {
            return false;
        }

        actionView.HorizontalOptions = LayoutOptions.Fill;
        actionView.VerticalOptions = LayoutOptions.Center;

        _addToVaultHost.Content = actionView;
        _addToVaultHost.IsVisible = true;
        return true;
    }

    protected void UpdateGeneratedPassword(string? password)
    {
        var normalized = string.IsNullOrWhiteSpace(password) ? null : password;

        LastGeneratedPassword = normalized;

        if (normalized is not null)
        {
            PasswordGenerated?.Invoke(this, normalized);
        }
        else
        {
            PasswordCleared?.Invoke(this, EventArgs.Empty);
        }
    }

    /// <summary>
    /// Animates a button to provide visual feedback when clicked.
    /// </summary>
    protected static async Task AnimateCopyButton(Button button)
    {
        var originalColor = button.BackgroundColor ?? Color.FromArgb("#4A5CFF");
        var highlightColor = Color.FromArgb("#6B7DFF");

        // Cancel any existing animations
        button.AbortAnimation("CopyButtonAnimation1");
        button.AbortAnimation("CopyButtonAnimation2");

        // Animate to highlight color
        var animation1 = new Animation(
            value => button.BackgroundColor = LerpColor(originalColor, highlightColor, value),
            0, 1, Easing.CubicOut);
        animation1.Commit(button, "CopyButtonAnimation1", 16, 100, Easing.CubicOut, (v, c) =>
        {
            // Ensure we're at highlight color when animation completes
            button.BackgroundColor = highlightColor;
        });

        await Task.Delay(100);

        // Animate back to original color
        var animation2 = new Animation(
            value => button.BackgroundColor = LerpColor(highlightColor, originalColor, value),
            0, 1, Easing.CubicIn);
        animation2.Commit(button, "CopyButtonAnimation2", 16, 150, Easing.CubicIn, (v, c) =>
        {
            // Ensure we're back to original color when animation completes
            button.BackgroundColor = originalColor;
        });

        await Task.Delay(150);
        
        // Final safety check - ensure original color is set
        button.BackgroundColor = originalColor;
    }

    private static Color LerpColor(Color from, Color to, double t)
    {
        var r = from.Red + (to.Red - from.Red) * t;
        var g = from.Green + (to.Green - from.Green) * t;
        var b = from.Blue + (to.Blue - from.Blue) * t;
        var a = from.Alpha + (to.Alpha - from.Alpha) * t;
        return Color.FromRgba(r, g, b, a);
    }
}
