using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Vault;

namespace Password_Phrase_Producer.ViewModels;

public class VaultSettingsViewModel : INotifyPropertyChanged
{
    private readonly PasswordVaultService _vaultService;
    private readonly IBiometricAuthenticationService _biometricAuthenticationService;
    private readonly TotpEncryptionService _totpEncryptionService;
    private readonly Command _changePasswordCommand;
    private readonly Command _changeAuthenticatorPasswordCommand;
    private bool _isListening;

    private bool _isVaultUnlocked;
    private bool _canUseBiometric;
    private bool _isBiometricConfigured;
    private bool _enableBiometric;
    private string _newMasterPassword = string.Empty;
    private string _confirmMasterPassword = string.Empty;
    private string? _changePasswordError;
    private string? _changePasswordSuccess;
    private bool _isPasswordChangeBusy;

    private bool _hasAuthenticatorPassword;
    private string _currentAuthenticatorPassword = string.Empty;
    private string _newAuthenticatorPassword = string.Empty;
    private string _confirmAuthenticatorPassword = string.Empty;
    private string? _changeAuthenticatorPasswordError;
    private string? _changeAuthenticatorPasswordSuccess;
    private bool _isAuthenticatorPasswordChangeBusy;

    public VaultSettingsViewModel(
        PasswordVaultService vaultService,
        IBiometricAuthenticationService biometricAuthenticationService,
        TotpEncryptionService totpEncryptionService)
    {
        _vaultService = vaultService;
        _biometricAuthenticationService = biometricAuthenticationService;
        _totpEncryptionService = totpEncryptionService;

        _changePasswordCommand = new Command(async () => await ChangeMasterPasswordAsync(), () => !IsPasswordChangeBusy && IsVaultUnlocked);
        ChangePasswordCommand = _changePasswordCommand;

        _changeAuthenticatorPasswordCommand = new Command(async () => await ChangeAuthenticatorPasswordAsync(), () => !IsAuthenticatorPasswordChangeBusy);
        ChangeAuthenticatorPasswordCommand = _changeAuthenticatorPasswordCommand;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand ChangePasswordCommand { get; }
    public ICommand ChangeAuthenticatorPasswordCommand { get; }

    public bool IsVaultUnlocked
    {
        get => _isVaultUnlocked;
        private set
        {
            if (SetProperty(ref _isVaultUnlocked, value))
            {
                UpdatePasswordCommandState();
            }
        }
    }

    public bool CanUseBiometric
    {
        get => _canUseBiometric;
        private set
        {
            if (SetProperty(ref _canUseBiometric, value))
            {
                UpdatePasswordCommandState();
            }
        }
    }

    public bool IsBiometricConfigured
    {
        get => _isBiometricConfigured;
        private set => SetProperty(ref _isBiometricConfigured, value);
    }

    public bool EnableBiometric
    {
        get => _enableBiometric;
        set
        {
            if (SetProperty(ref _enableBiometric, value))
            {
                UpdatePasswordCommandState();
            }
        }
    }

    public string NewMasterPassword
    {
        get => _newMasterPassword;
        set
        {
            if (SetProperty(ref _newMasterPassword, value))
            {
                ClearPasswordFeedback();
                UpdatePasswordCommandState();
            }
        }
    }

    public string ConfirmMasterPassword
    {
        get => _confirmMasterPassword;
        set
        {
            if (SetProperty(ref _confirmMasterPassword, value))
            {
                ClearPasswordFeedback();
                UpdatePasswordCommandState();
            }
        }
    }

    public string? ChangePasswordError
    {
        get => _changePasswordError;
        private set => SetProperty(ref _changePasswordError, value);
    }

    public string? ChangePasswordSuccess
    {
        get => _changePasswordSuccess;
        private set => SetProperty(ref _changePasswordSuccess, value);
    }

    public bool IsPasswordChangeBusy
    {
        get => _isPasswordChangeBusy;
        private set
        {
            if (SetProperty(ref _isPasswordChangeBusy, value))
            {
                UpdatePasswordCommandState();
            }
        }
    }

    public bool HasAuthenticatorPassword
    {
        get => _hasAuthenticatorPassword;
        private set
        {
            if (SetProperty(ref _hasAuthenticatorPassword, value))
            {
                UpdateAuthenticatorPasswordCommandState();
            }
        }
    }

    public string CurrentAuthenticatorPassword
    {
        get => _currentAuthenticatorPassword;
        set
        {
            if (SetProperty(ref _currentAuthenticatorPassword, value))
            {
                ClearAuthenticatorPasswordFeedback();
                UpdateAuthenticatorPasswordCommandState();
            }
        }
    }

    public string NewAuthenticatorPassword
    {
        get => _newAuthenticatorPassword;
        set
        {
            if (SetProperty(ref _newAuthenticatorPassword, value))
            {
                ClearAuthenticatorPasswordFeedback();
                UpdateAuthenticatorPasswordCommandState();
            }
        }
    }

    public string ConfirmAuthenticatorPassword
    {
        get => _confirmAuthenticatorPassword;
        set
        {
            if (SetProperty(ref _confirmAuthenticatorPassword, value))
            {
                ClearAuthenticatorPasswordFeedback();
                UpdateAuthenticatorPasswordCommandState();
            }
        }
    }

    public string? ChangeAuthenticatorPasswordError
    {
        get => _changeAuthenticatorPasswordError;
        private set => SetProperty(ref _changeAuthenticatorPasswordError, value);
    }

    public string? ChangeAuthenticatorPasswordSuccess
    {
        get => _changeAuthenticatorPasswordSuccess;
        private set => SetProperty(ref _changeAuthenticatorPasswordSuccess, value);
    }

    public bool IsAuthenticatorPasswordChangeBusy
    {
        get => _isAuthenticatorPasswordChangeBusy;
        private set
        {
            if (SetProperty(ref _isAuthenticatorPasswordChangeBusy, value))
            {
                UpdateAuthenticatorPasswordCommandState();
            }
        }
    }

    public void Activate()
    {
        if (_isListening)
        {
            return;
        }

        _isListening = true;
    }

    public void Deactivate()
    {
        if (!_isListening)
        {
            return;
        }

        _isListening = false;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await RefreshVaultStateAsync(cancellationToken).ConfigureAwait(false);
        await RefreshAuthenticatorStateAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RefreshVaultStateAsync(CancellationToken cancellationToken = default)
    {
        var unlocked = _vaultService.IsUnlocked;
        var canUseBiometric = await _biometricAuthenticationService.IsAvailableAsync(cancellationToken).ConfigureAwait(false);
        var biometricConfigured = canUseBiometric && await _vaultService.HasBiometricKeyAsync(cancellationToken).ConfigureAwait(false);

        await MainThread.InvokeOnMainThreadAsync(() =>
        {
            IsVaultUnlocked = unlocked;
            CanUseBiometric = canUseBiometric;
            IsBiometricConfigured = biometricConfigured;
            EnableBiometric = biometricConfigured;

            if (!unlocked)
            {
                NewMasterPassword = string.Empty;
                ConfirmMasterPassword = string.Empty;
            }

            ClearPasswordFeedback();
        }).ConfigureAwait(false);
    }

    public async Task RefreshAuthenticatorStateAsync(CancellationToken cancellationToken = default)
    {
        // No async work today, but keep signature for symmetry/future changes
        await MainThread.InvokeOnMainThreadAsync(() =>
        {
            HasAuthenticatorPassword = _totpEncryptionService.HasPassword;

            // Clear fields if the authenticator is not configured yet
            if (!HasAuthenticatorPassword)
            {
                CurrentAuthenticatorPassword = string.Empty;
            }

            NewAuthenticatorPassword = string.Empty;
            ConfirmAuthenticatorPassword = string.Empty;
            ClearAuthenticatorPasswordFeedback();
        }).ConfigureAwait(false);
    }

    public Task<byte[]> CreateBackupAsync(CancellationToken cancellationToken = default)
        => _vaultService.CreateBackupAsync(cancellationToken);

    public Task RestoreBackupAsync(Stream backupStream, CancellationToken cancellationToken = default)
        => _vaultService.RestoreBackupAsync(backupStream, cancellationToken);

    public Task<byte[]> ExportEncryptedVaultAsync(CancellationToken cancellationToken = default)
        => _vaultService.ExportEncryptedVaultAsync(cancellationToken);

    public Task ImportEncryptedVaultAsync(Stream encryptedStream, CancellationToken cancellationToken = default)
        => _vaultService.ImportEncryptedVaultAsync(encryptedStream, cancellationToken);

    private async Task ChangeMasterPasswordAsync()
    {
        if (IsPasswordChangeBusy)
        {
            return;
        }

        try
        {
            IsPasswordChangeBusy = true;
            ClearPasswordFeedback();

            if (!IsVaultUnlocked)
            {
                ChangePasswordError = "Der Tresor muss entsperrt sein, bevor du das Passwort ändern kannst.";
                return;
            }

            if (string.IsNullOrWhiteSpace(NewMasterPassword))
            {
                ChangePasswordError = "Bitte gib ein neues Master-Passwort ein.";
                return;
            }

            if (!string.Equals(NewMasterPassword, ConfirmMasterPassword, StringComparison.Ordinal))
            {
                ChangePasswordError = "Die Passwörter stimmen nicht überein.";
                return;
            }

            await _vaultService.ChangeMasterPasswordAsync(NewMasterPassword, EnableBiometric && CanUseBiometric).ConfigureAwait(false);

            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                NewMasterPassword = string.Empty;
                ConfirmMasterPassword = string.Empty;
                ChangePasswordSuccess = "Master-Passwort wurde aktualisiert.";
                IsBiometricConfigured = EnableBiometric && CanUseBiometric;
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                ChangePasswordError = ex.Message;
                ChangePasswordSuccess = null;
            }).ConfigureAwait(false);
        }
        finally
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsPasswordChangeBusy = false).ConfigureAwait(false);
        }
    }

    private async Task ChangeAuthenticatorPasswordAsync()
    {
        if (IsAuthenticatorPasswordChangeBusy)
        {
            return;
        }

        try
        {
            IsAuthenticatorPasswordChangeBusy = true;
            ClearAuthenticatorPasswordFeedback();

            if (string.IsNullOrWhiteSpace(NewAuthenticatorPassword))
            {
                ChangeAuthenticatorPasswordError = "Bitte gib ein neues Authenticator-Passwort ein.";
                return;
            }

            if (!string.Equals(NewAuthenticatorPassword, ConfirmAuthenticatorPassword, StringComparison.Ordinal))
            {
                ChangeAuthenticatorPasswordError = "Die Passwörter stimmen nicht überein.";
                return;
            }

            if (_totpEncryptionService.HasPassword)
            {
                if (string.IsNullOrWhiteSpace(CurrentAuthenticatorPassword))
                {
                    ChangeAuthenticatorPasswordError = "Bitte gib dein aktuelles Authenticator-Passwort ein.";
                    return;
                }

                await _totpEncryptionService.ChangePasswordAsync(CurrentAuthenticatorPassword, NewAuthenticatorPassword).ConfigureAwait(false);
            }
            else
            {
                // Not configured yet -> initial setup from settings
                await _totpEncryptionService.SetupPasswordAsync(NewAuthenticatorPassword).ConfigureAwait(false);
            }

            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                HasAuthenticatorPassword = _totpEncryptionService.HasPassword;
                CurrentAuthenticatorPassword = string.Empty;
                NewAuthenticatorPassword = string.Empty;
                ConfirmAuthenticatorPassword = string.Empty;
                ChangeAuthenticatorPasswordSuccess = "Authenticator-Passwort wurde aktualisiert.";
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                ChangeAuthenticatorPasswordError = ex.Message;
                ChangeAuthenticatorPasswordSuccess = null;
            }).ConfigureAwait(false);
        }
        finally
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsAuthenticatorPasswordChangeBusy = false).ConfigureAwait(false);
        }
    }

    private void UpdatePasswordCommandState()
    {
        if (_changePasswordCommand is not null)
        {
            MainThread.BeginInvokeOnMainThread(_changePasswordCommand.ChangeCanExecute);
        }
    }

    private void UpdateAuthenticatorPasswordCommandState()
    {
        if (_changeAuthenticatorPasswordCommand is not null)
        {
            MainThread.BeginInvokeOnMainThread(_changeAuthenticatorPasswordCommand.ChangeCanExecute);
        }
    }

    private void ClearPasswordFeedback()
    {
        ChangePasswordError = null;
        ChangePasswordSuccess = null;
    }

    private void ClearAuthenticatorPasswordFeedback()
    {
        ChangeAuthenticatorPasswordError = null;
        ChangeAuthenticatorPasswordSuccess = null;
    }

    private bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
