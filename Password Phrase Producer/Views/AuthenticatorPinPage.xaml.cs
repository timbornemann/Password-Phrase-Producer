using Password_Phrase_Producer.Services.Security;

namespace Password_Phrase_Producer.Views;

public partial class AuthenticatorPinPage : ContentPage
{
    private readonly TotpEncryptionService _encryptionService;
    private readonly bool _isSetupMode;

    public AuthenticatorPinPage(TotpEncryptionService encryptionService)
    {
        InitializeComponent();
        _encryptionService = encryptionService;
        _isSetupMode = !_encryptionService.HasPassword;

        if (_isSetupMode)
        {
            TitleLabel.Text = "Authenticator einrichten";
            SubtitleLabel.Text = "Erstelle ein Passwort zum Schutz deiner 2FA-Codes";
            UnlockButton.Text = "Passwort erstellen";
            ConfirmPinBorder.IsVisible = true;
            HintLabel.IsVisible = true;
        }
    }

    private async void OnUnlockClicked(object sender, EventArgs e)
    {
        var password = PinEntry.Text?.Trim();
        
        if (string.IsNullOrWhiteSpace(password))
        {
            ShowError("Bitte Passwort eingeben");
            return;
        }

        if (_isSetupMode)
        {
            // Setup mode: verify password confirmation
            var confirmPassword = ConfirmPinEntry.Text?.Trim();
            
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
                UnlockButton.IsEnabled = false;
                UnlockButton.Text = "Erstelle...";
                
                await _encryptionService.SetupPasswordAsync(password);
                await Navigation.PopModalAsync();
            }
            catch (Exception ex)
            {
                ShowError($"Fehler: {ex.Message}");
                UnlockButton.IsEnabled = true;
                UnlockButton.Text = "Passwort erstellen";
            }
        }
        else
        {
            // Unlock mode
            try
            {
                UnlockButton.IsEnabled = false;
                UnlockButton.Text = "Entsperre...";
                
                var success = await _encryptionService.UnlockWithPasswordAsync(password);
                
                if (success)
                {
                    await Navigation.PopModalAsync();
                }
                else
                {
                    ShowError("Falsches Passwort");
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
        }
    }

    private void OnPinEntered(object sender, EventArgs e)
    {
        if (_isSetupMode)
        {
            ConfirmPinEntry.Focus();
        }
        else
        {
            OnUnlockClicked(sender, e);
        }
    }

    private void OnConfirmPinEntered(object sender, EventArgs e)
    {
        OnUnlockClicked(sender, e);
    }

    private void ShowError(string message)
    {
        ErrorLabel.Text = message;
        ErrorLabel.IsVisible = true;
        
        // Hide error after 3 seconds
        Task.Run(async () =>
        {
            await Task.Delay(3000);
            MainThread.BeginInvokeOnMainThread(() =>
            {
                ErrorLabel.IsVisible = false;
            });
        });
    }

    protected override bool OnBackButtonPressed()
    {
        // Don't allow back button in setup mode
        return _isSetupMode;
    }
}

