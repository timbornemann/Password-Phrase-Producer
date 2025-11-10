using System;
using Microsoft.Maui.Controls;
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
}
