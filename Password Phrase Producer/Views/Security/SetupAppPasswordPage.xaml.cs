using System;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Services.Security;

namespace Password_Phrase_Producer.Views.Security;

public partial class SetupAppPasswordPage : ContentPage
{
    private readonly IAppLockService _appLockService;

    public SetupAppPasswordPage(IAppLockService appLockService)
    {
        InitializeComponent();
        _appLockService = appLockService;
    }

    private async void OnSetupClicked(object sender, EventArgs e)
    {
        var password = PasswordEntry.Text;
        var confirm = ConfirmPasswordEntry.Text;

        if (string.IsNullOrWhiteSpace(password))
        {
            ShowError("Bitte Passwort eingeben.");
            return;
        }

        if (password != confirm)
        {
            ShowError("Passwörter stimmen nicht überein.");
            return;
        }

        ErrorLabel.IsVisible = false;

        try
        {
            await _appLockService.SetupAsync(password, BiometricSwitch.IsToggled);
            Application.Current.MainPage = new AppShell();
        }
        catch (Exception ex)
        {
            ShowError($"Fehler beim Einrichten: {ex.Message}");
        }
    }

    private void ShowError(string message)
    {
        ErrorLabel.Text = message;
        ErrorLabel.IsVisible = true;
    }
}
