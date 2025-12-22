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
    private readonly Command _changePasswordCommand;
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

    public VaultSettingsViewModel(
        PasswordVaultService vaultService,
        IBiometricAuthenticationService biometricAuthenticationService)
    {
        _vaultService = vaultService;
        _biometricAuthenticationService = biometricAuthenticationService;

        _changePasswordCommand = new Command(async () => await ChangeMasterPasswordAsync(), () => !IsPasswordChangeBusy && IsVaultUnlocked);
        ChangePasswordCommand = _changePasswordCommand;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand ChangePasswordCommand { get; }

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
        => await RefreshVaultStateAsync(cancellationToken).ConfigureAwait(false);

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

    private void UpdatePasswordCommandState()
    {
        if (_changePasswordCommand is not null)
        {
            MainThread.BeginInvokeOnMainThread(_changePasswordCommand.ChangeCanExecute);
        }
    }

    private void ClearPasswordFeedback()
    {
        ChangePasswordError = null;
        ChangePasswordSuccess = null;
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
