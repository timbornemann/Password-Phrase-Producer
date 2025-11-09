using System;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Views;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public abstract class PasswordGeneratorContentView : ContentView, IPasswordResultProvider
{
    private string? _lastGeneratedPassword;

    public event EventHandler<string>? PasswordGenerated;

    public event EventHandler? PasswordCleared;

    public string? LastGeneratedPassword
    {
        get => _lastGeneratedPassword;
        private set => _lastGeneratedPassword = value;
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
