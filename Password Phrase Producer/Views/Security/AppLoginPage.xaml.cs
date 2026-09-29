using System;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Services.Security;

namespace Password_Phrase_Producer.Views.Security;

public partial class AppLoginPage : ContentPage
{
    private readonly IAppLockService _appLockService;
    private readonly IUnlockAttemptGate _attemptGate;
    private readonly IRecoveryQuestionsService _recoveryQuestions;
    private Microsoft.Maui.Dispatching.IDispatcherTimer? _timer;
    private bool _isBusy;
    private bool _refreshing;

    public AppLoginPage(IAppLockService appLockService, IUnlockAttemptGate attemptGate,
        IRecoveryQuestionsService recoveryQuestions)
    {
        InitializeComponent();
        _appLockService = appLockService;
        _attemptGate = attemptGate;
        _recoveryQuestions = recoveryQuestions;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        try
        {
            await RefreshStatusAsync();
            await CheckBiometricAvailabilityAsync();
            if (Application.Current?.MainPage != this) return;
            _timer?.Stop();
            _timer = Dispatcher.CreateTimer();
            _timer.Interval = TimeSpan.FromSeconds(1);
            _timer.Tick += async (_, _) => await RefreshStatusAsync();
            _timer.Start();
            PasswordEntry.Focus();
        }
        catch (Exception ex)
        {
            UnlockButton.IsEnabled = PasswordEntry.IsEnabled = BiometricButton.IsEnabled = false;
            ErrorLabel.Text = ex.Message;
            ErrorLabel.IsVisible = true;
        }
    }

    private async Task CheckBiometricAvailabilityAsync()
    {
        if (await _appLockService.IsBiometricConfiguredAsync())
        {
            BiometricButton.IsVisible = true;
            // Auto-trigger biometric prompt
            if ((await _attemptGate.GetStatusAsync(ProtectedAccess.App)).CanUseBiometrics)
                await UnlockWithBiometricsAsync();
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
        if (_isBusy) return;
        var password = PasswordEntry.Text;
        if (string.IsNullOrWhiteSpace(password))
        {
            ErrorLabel.Text = "Bitte Passwort eingeben.";
            ErrorLabel.IsVisible = true;
            return;
        }

        _isBusy = true;
        try
        {
            var success = await _appLockService.UnlockAsync(password);
            if (success)
            {
                Application.Current!.MainPage = new AppShell();
            }
            else
            {
                ErrorLabel.Text = "Passwort ungültig oder Zugang gesperrt.";
                ErrorLabel.IsVisible = true;
                PasswordEntry.Text = string.Empty;
            }
        }
        catch (Exception ex)
        {
            ErrorLabel.Text = ex.Message;
            ErrorLabel.IsVisible = true;
        }
        finally { _isBusy = false; await RefreshStatusAsync(); }
    }

    private async void OnBiometricClicked(object sender, EventArgs e)
    {
        await UnlockWithBiometricsAsync();
    }

    private async Task UnlockWithBiometricsAsync()
    {
        if (_isBusy) return;
        _isBusy = true;
        try
        {
            var success = await _appLockService.UnlockWithBiometricsAsync();
            if (success)
                Application.Current!.MainPage = new AppShell();
            else
            {
                ErrorLabel.Text = "Biometrische Entsperrung fehlgeschlagen oder abgebrochen.";
                ErrorLabel.IsVisible = true;
            }
        }
        catch (Exception ex)
        {
            ErrorLabel.Text = ex.Message;
            ErrorLabel.IsVisible = true;
        }
        finally { _isBusy = false; await RefreshStatusAsync(); }
    }

    private async void OnRecoveryClicked(object sender, EventArgs e)
    {
        if (_isBusy) return;
        try
        {
            var page = new RecoveryChallengePage(_recoveryQuestions, _attemptGate, ProtectedAccess.App);
            await Navigation.PushModalAsync(page);
            await page.WaitForCloseAsync();
            await RefreshStatusAsync();
        }
        catch (Exception ex) { ErrorLabel.Text = ex.Message; ErrorLabel.IsVisible = true; }
    }

    private async Task RefreshStatusAsync()
    {
        if (_refreshing) return;
        _refreshing = true;
        try
        {
            var status = await _attemptGate.GetStatusAsync(ProtectedAccess.App);
            var locked = status.IsLocked;
            UnlockButton.IsEnabled = !locked && !_isBusy;
            PasswordEntry.IsEnabled = !locked && !_isBusy;
            BiometricButton.IsEnabled = status.CanUseBiometrics && !_isBusy;
            RecoveryButton.IsVisible = status.CanUseRecovery && await _recoveryQuestions.IsConfiguredAsync();
            AttemptStatusLabel.Text = locked
                ? $"Gesperrt für {FormatRemaining(status.LockedUntil!.Value)}"
                : $"Noch {status.PasswordAttemptsRemaining} Passwort{(status.PasswordAttemptsRemaining == 1 ? "versuch" : "versuche")}";
        }
        catch (Exception ex)
        {
            UnlockButton.IsEnabled = PasswordEntry.IsEnabled = BiometricButton.IsEnabled = false;
            AttemptStatusLabel.Text = ex.Message;
        }
        finally { _refreshing = false; }
    }

    private static string FormatRemaining(DateTimeOffset until)
    {
        var remaining = until - DateTimeOffset.UtcNow;
        if (remaining < TimeSpan.Zero) remaining = TimeSpan.Zero;
        return $"{(int)remaining.TotalHours:00}:{remaining.Minutes:00}:{remaining.Seconds:00}";
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _timer?.Stop();
        PasswordEntry.Text = string.Empty;
    }
}
