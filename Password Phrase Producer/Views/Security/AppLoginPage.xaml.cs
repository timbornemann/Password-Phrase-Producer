using System;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Services.Security;

namespace Password_Phrase_Producer.Views.Security;

public partial class AppLoginPage : ContentPage
{
    private readonly IAppLockService _appLockService;

    public AppLoginPage(IAppLockService appLockService)
    {
        InitializeComponent();
        _appLockService = appLockService;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        await CheckBiometricAvailabilityAsync();
        PasswordEntry.Focus();
    }

    private async Task CheckBiometricAvailabilityAsync()
    {
        if (await _appLockService.IsBiometricConfiguredAsync())
        {
            BiometricButton.IsVisible = true;
            // Optional: Auto-trigger biometric prompt? 
            // await UnlockWithBiometricsAsync();
        }
        else
        {
            BiometricButton.IsVisible = false;
        }
    }

    private async void OnUnlockClicked(object sender, EventArgs e)
    {
        await UnlockWithPasswordAsync();
    }

    private async void OnPasswordCompleted(object sender, EventArgs e)
    {
        await UnlockWithPasswordAsync();
    }

    private async Task UnlockWithPasswordAsync()
    {
        var password = PasswordEntry.Text;
        if (string.IsNullOrWhiteSpace(password))
        {
            ErrorLabel.Text = "Bitte Passwort eingeben.";
            ErrorLabel.IsVisible = true;
            return;
        }

        var success = await _appLockService.UnlockAsync(password);
        if (success)
        {
            Application.Current.MainPage = new AppShell();
        }
        else
        {
            ErrorLabel.Text = "Falsches Passwort.";
            ErrorLabel.IsVisible = true;
            PasswordEntry.Text = string.Empty;
        }
    }

    private async void OnBiometricClicked(object sender, EventArgs e)
    {
        await UnlockWithBiometricsAsync();
    }

    private async Task UnlockWithBiometricsAsync()
    {
        var success = await _appLockService.UnlockWithBiometricsAsync();
        if (success)
        {
            Application.Current.MainPage = new AppShell();
        }
        else
        {
            ErrorLabel.Text = "Biometrische Entsperrung fehlgeschlagen.";
            ErrorLabel.IsVisible = true;
        }
    }
}
