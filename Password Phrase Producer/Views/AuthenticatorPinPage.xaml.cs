using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Views.Security;

namespace Password_Phrase_Producer.Views;

public partial class AuthenticatorPinPage : ContentPage
{
    private readonly TotpEncryptionService _encryptionService;
    private readonly IBiometricAuthenticationService _biometricService;
    private readonly IUnlockAttemptGate _attemptGate;
    private readonly IRecoveryQuestionsService _recoveryQuestions;
    private Microsoft.Maui.Dispatching.IDispatcherTimer? _lockoutTimer;
    private bool _refreshingLockout;
    private bool _isSetupMode;
    private bool _isBusy;

    public AuthenticatorPinPage(TotpEncryptionService encryptionService, IBiometricAuthenticationService biometricService,
        IUnlockAttemptGate attemptGate, IRecoveryQuestionsService recoveryQuestions)
    {
        InitializeComponent();
        _encryptionService = encryptionService;
        _biometricService = biometricService;
        _attemptGate = attemptGate;
        _recoveryQuestions = recoveryQuestions;
        if (OperatingSystem.IsWindows())
        {
            BiometricSetupLabel.Text = "Windows Hello (PIN oder Biometrie) für den Authenticator aktivieren";
            BiometricUnlockButton.Text = "Mit Windows Hello entsperren";
        }
        
        // Initial state (will be updated in OnAppearing)
        TitleLabel.Text = "Lade...";
        UnlockButton.IsEnabled = false;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        try
        {
            _isSetupMode = !await _encryptionService.HasPasswordAsync();
            var canUseBiometrics = await _biometricService.IsAvailableAsync();
            var hasBiometricKey = !_isSetupMode && await _encryptionService.HasBiometricKeyAsync();
            BiometricSetupRow.IsVisible = canUseBiometrics && !hasBiometricKey;
            BiometricUnlockButton.IsVisible = canUseBiometrics && hasBiometricKey;
            UpdateUiState();
            await RefreshLockoutAsync();
            _lockoutTimer?.Stop();
            _lockoutTimer = Dispatcher.CreateTimer();
            _lockoutTimer.Interval = TimeSpan.FromSeconds(1);
            _lockoutTimer.Tick += async (_, _) => await RefreshLockoutAsync();
            _lockoutTimer.Start();
        }
        catch (Exception ex)
        {
            ShowError($"Fehler beim Laden: {ex.Message}");
        }
    }

    private async void OnRecoveryClicked(object? sender, EventArgs e)
    {
        if (_isBusy) return;
        try
        {
            var page = new RecoveryChallengePage(_recoveryQuestions, _attemptGate, ProtectedAccess.Authenticator);
            await Navigation.PushModalAsync(page);
            await page.WaitForCloseAsync();
            await RefreshLockoutAsync();
        }
        catch (Exception ex) { ShowError(ex.Message); }
    }

    private async Task RefreshLockoutAsync()
    {
        if (_refreshingLockout) return;
        _refreshingLockout = true;
        try
        {
            if (_isSetupMode)
            {
                AttemptStatusLabel.IsVisible = false;
                RecoveryButton.IsVisible = false;
                return;
            }
            var status = await _attemptGate.GetStatusAsync(ProtectedAccess.Authenticator);
            AttemptStatusLabel.IsVisible = true;
            AttemptStatusLabel.Text = status.IsLocked
                ? $"Gesperrt für {FormatLockout(status.LockedUntil!.Value)}"
                : $"Noch {status.PasswordAttemptsRemaining} Passwort{(status.PasswordAttemptsRemaining == 1 ? "versuch" : "versuche")}";
            UnlockButton.IsEnabled = PinEntry.IsEnabled = !status.IsLocked && !_isBusy;
            BiometricUnlockButton.IsEnabled = status.CanUseBiometrics && !_isBusy;
            RecoveryButton.IsVisible = status.CanUseRecovery && await _recoveryQuestions.IsConfiguredAsync();
        }
        catch (Exception ex)
        {
            UnlockButton.IsEnabled = PinEntry.IsEnabled = BiometricUnlockButton.IsEnabled = false;
            AttemptStatusLabel.IsVisible = true;
            AttemptStatusLabel.Text = ex.Message;
            RecoveryButton.IsVisible = false;
        }
        finally { _refreshingLockout = false; }
    }

    private static string FormatLockout(DateTimeOffset until)
    {
        var remaining = until - DateTimeOffset.UtcNow;
        if (remaining < TimeSpan.Zero) remaining = TimeSpan.Zero;
        return $"{(int)remaining.TotalHours:00}:{remaining.Minutes:00}:{remaining.Seconds:00}";
    }

    private void UpdateUiState()
    {
        UnlockButton.IsEnabled = true;
        BiometricUnlockButton.IsEnabled = true;
        if (_isSetupMode)
        {
            TitleLabel.Text = "Authenticator einrichten";
            SubtitleLabel.Text = "Bitte gib dein Master-Passwort ein.";
            UnlockButton.Text = "Passwort erstellen";
            ConfirmPinEntry.IsVisible = true;
            BackButton.IsVisible = false; // Kein Zurück im Setup-Mode
        }
        else
        {
            TitleLabel.Text = "Authenticator gesperrt";
            SubtitleLabel.Text = "Bitte gib dein Master-Passwort ein.";
            UnlockButton.Text = "Entsperren";
            ConfirmPinEntry.IsVisible = false;
            BackButton.IsVisible = true; // Zurück-Button im Unlock-Mode
        }
    }

    private async void OnBackTapped(object? sender, TappedEventArgs e)
    {
        if (_isBusy) return;
        // Modal schließen
        await Navigation.PopModalAsync();
        
        // Zur Startseite navigieren
        if (Shell.Current is not null)
        {
            await Shell.Current.GoToAsync("//home");
        }
    }

    private async void OnUnlockClicked(object sender, EventArgs e)
    {
        if (_isBusy) return;
        var password = PinEntry.Text;
        
        if (string.IsNullOrWhiteSpace(password))
        {
            ShowError("Bitte Passwort eingeben");
            return;
        }

        if (_isSetupMode)
        {
            // Setup mode: verify password confirmation
            var confirmPassword = ConfirmPinEntry.Text;
            
            if (string.IsNullOrWhiteSpace(confirmPassword))
            {
                ShowError("Bitte Passwort bestätigen");
                return;
            }

            if (password != confirmPassword)
            {
                ShowError("Passwörter stimmen nicht überein");
                PinEntry.Text = string.Empty;
                ConfirmPinEntry.Text = string.Empty;
                PinEntry.Focus();
                return;
            }

            // Create password
            try
            {
                _isBusy = true;
                UnlockButton.IsEnabled = false;
                BiometricUnlockButton.IsEnabled = false;
                UnlockButton.Text = "Erstelle...";
                
                await _encryptionService.SetupPasswordAsync(password);
                await EnableBiometricsIfRequestedAsync();
                await Navigation.PopModalAsync();
            }
            catch (Exception ex)
            {
                ShowError($"Fehler: {ex.Message}");
                UnlockButton.IsEnabled = true;
                UnlockButton.Text = _encryptionService.IsUnlocked ? "Entsperren" : "Passwort erstellen";
                BiometricUnlockButton.IsEnabled = true;
                _isSetupMode = !await _encryptionService.HasPasswordAsync();
                UpdateUiState();
            }
            finally { _isBusy = false; await RefreshLockoutAsync(); }
        }
        else
        {
            // Unlock mode
            try
            {
                _isBusy = true;
                UnlockButton.IsEnabled = false;
                BiometricUnlockButton.IsEnabled = false;
                UnlockButton.Text = "Entsperre...";
                
                var success = await _encryptionService.UnlockWithPasswordAsync(password);
                
                if (success)
                {
                    await EnableBiometricsIfRequestedAsync();
                    await Navigation.PopModalAsync();
                }
                else
                {
                    ShowError("Passwort falsch oder Authenticator-Daten beschädigt.");
                    PinEntry.Text = string.Empty;
                    PinEntry.Focus();
                    UnlockButton.IsEnabled = true;
                    UnlockButton.Text = "Entsperren";
                }
            }
            catch (Exception ex)
            {
                ShowError($"Fehler: {ex.Message}");
                UnlockButton.IsEnabled = true;
                UnlockButton.Text = "Entsperren";
            }
            finally
            {
                BiometricUnlockButton.IsEnabled = true;
                _isBusy = false;
                await RefreshLockoutAsync();
            }
        }
    }

    private async Task EnableBiometricsIfRequestedAsync()
    {
        if (!BiometricSetupRow.IsVisible || !BiometricSetupSwitch.IsToggled) return;
        try
        {
            await _encryptionService.SetBiometricUnlockAsync(true);
        }
        catch (Exception ex)
        {
            // Password unlock is already valid. Make the optional setup failure visible.
            await DisplayAlert("Biometrie nicht aktiviert", ex.Message, "OK");
        }
    }

    private async void OnBiometricUnlockClicked(object sender, EventArgs e)
    {
        if (_isBusy) return;
        try
        {
            _isBusy = true;
            UnlockButton.IsEnabled = false;
            BiometricUnlockButton.IsEnabled = false;
            if (await _encryptionService.UnlockWithBiometricsAsync())
                await Navigation.PopModalAsync();
            else
                ShowError("Biometrische Entsperrung fehlgeschlagen. Verwende dein Passwort.");
        }
        catch (Exception ex)
        {
            ShowError($"Biometrische Entsperrung fehlgeschlagen: {ex.Message}");
        }
        finally
        {
            _isBusy = false;
            UnlockButton.IsEnabled = true;
            BiometricUnlockButton.IsEnabled = true;
            await RefreshLockoutAsync();
        }
    }

    private void OnPinEntered(object sender, EventArgs e)
    {
        if (_isBusy || !UnlockButton.IsEnabled) return;

        if (_isSetupMode && string.IsNullOrEmpty(ConfirmPinEntry.Text))
        {
            ConfirmPinEntry.Focus();
        }
        else
        {
            OnUnlockClicked(UnlockButton, EventArgs.Empty);
        }
    }

    private void OnConfirmPinEntered(object sender, EventArgs e)
    {
        if (_isBusy || !UnlockButton.IsEnabled) return;
        OnUnlockClicked(UnlockButton, EventArgs.Empty);
    }

    private void ShowError(string message)
    {
        ErrorLabel.Text = message;
        ErrorLabel.IsVisible = !string.IsNullOrWhiteSpace(message);
        
        // Hide error after 3 seconds
        if (!string.IsNullOrWhiteSpace(message))
        {
            Task.Run(async () =>
            {
                await Task.Delay(3000);
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    ErrorLabel.IsVisible = false;
                    ErrorLabel.Text = string.Empty;
                });
            });
        }
    }

    protected override bool OnBackButtonPressed()
    {
        // Don't allow back button in setup mode
        return _isSetupMode;
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _lockoutTimer?.Stop();
        PinEntry.Text = string.Empty;
        ConfirmPinEntry.Text = string.Empty;
        BiometricSetupSwitch.IsToggled = false;
    }
}

