using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Vault;
using Password_Phrase_Producer.Services;

namespace Password_Phrase_Producer.ViewModels;

public class VaultSettingsViewModel : INotifyPropertyChanged
{
    private readonly PasswordVaultService _vaultService;
    private readonly DataVaultService _dataVaultService;
    private readonly IBiometricAuthenticationService _biometricAuthenticationService;
    private readonly TotpEncryptionService _totpEncryptionService;
    private readonly TotpService _totpService;
    private readonly Command _changePasswordCommand;
    private readonly Command _changeDataVaultPasswordCommand;
    private readonly Command _changeAuthenticatorPasswordCommand;
    private bool _isListening;
    private bool _hasVaultMasterPassword;
    private bool _hasDataVaultMasterPassword;

    private bool _isVaultUnlocked;
    private bool _canUseBiometric;
    private bool _isBiometricConfigured;
    private bool _enableBiometric;
    private string _currentMasterPassword = string.Empty;
    private string _newMasterPassword = string.Empty;
    private string _confirmMasterPassword = string.Empty;
    private string? _changePasswordError;
    private string? _changePasswordSuccess;
    private bool _isPasswordChangeBusy;

    private bool _isDataVaultUnlocked;
    private bool _canUseDataVaultBiometric;
    private bool _isDataVaultBiometricConfigured;
    private bool _enableDataVaultBiometric;
    private string _currentDataVaultMasterPassword = string.Empty;
    private string _newDataVaultMasterPassword = string.Empty;
    private string _confirmDataVaultMasterPassword = string.Empty;
    private string? _changeDataVaultPasswordError;
    private string? _changeDataVaultPasswordSuccess;
    private bool _isDataVaultPasswordChangeBusy;

    private bool _hasAuthenticatorPassword;
    private string _currentAuthenticatorPassword = string.Empty;
    private string _newAuthenticatorPassword = string.Empty;
    private string _confirmAuthenticatorPassword = string.Empty;
    private string? _changeAuthenticatorPasswordError;
    private string? _changeAuthenticatorPasswordSuccess;
    private bool _isAuthenticatorPasswordChangeBusy;

    public VaultSettingsViewModel(
        PasswordVaultService vaultService,
        DataVaultService dataVaultService,
        IBiometricAuthenticationService biometricAuthenticationService,
        TotpEncryptionService totpEncryptionService,
        TotpService totpService)
    {
        _vaultService = vaultService;
        _dataVaultService = dataVaultService;
        _biometricAuthenticationService = biometricAuthenticationService;
        _totpEncryptionService = totpEncryptionService;
        _totpService = totpService;

        _changePasswordCommand = new Command(async () => await ChangeMasterPasswordAsync(), () => !IsPasswordChangeBusy);
        ChangePasswordCommand = _changePasswordCommand;

        _changeDataVaultPasswordCommand = new Command(async () => await ChangeDataVaultPasswordAsync(), () => !IsDataVaultPasswordChangeBusy);
        ChangeDataVaultPasswordCommand = _changeDataVaultPasswordCommand;

        _changeAuthenticatorPasswordCommand = new Command(async () => await ChangeAuthenticatorPasswordAsync(), () => !IsAuthenticatorPasswordChangeBusy);
        ChangeAuthenticatorPasswordCommand = _changeAuthenticatorPasswordCommand;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ICommand ChangePasswordCommand { get; }
    public ICommand ChangeDataVaultPasswordCommand { get; }
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

    public string CurrentMasterPassword
    {
        get => _currentMasterPassword;
        set
        {
            if (SetProperty(ref _currentMasterPassword, value))
            {
                ClearPasswordFeedback();
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

    public bool IsDataVaultUnlocked
    {
        get => _isDataVaultUnlocked;
        private set
        {
            if (SetProperty(ref _isDataVaultUnlocked, value))
            {
                UpdateDataVaultPasswordCommandState();
            }
        }
    }

    public bool CanUseDataVaultBiometric
    {
        get => _canUseDataVaultBiometric;
        private set
        {
            if (SetProperty(ref _canUseDataVaultBiometric, value))
            {
                UpdateDataVaultPasswordCommandState();
            }
        }
    }

    public bool IsDataVaultBiometricConfigured
    {
        get => _isDataVaultBiometricConfigured;
        private set => SetProperty(ref _isDataVaultBiometricConfigured, value);
    }

    public bool EnableDataVaultBiometric
    {
        get => _enableDataVaultBiometric;
        set
        {
            if (SetProperty(ref _enableDataVaultBiometric, value))
            {
                UpdateDataVaultPasswordCommandState();
            }
        }
    }

    public string CurrentDataVaultMasterPassword
    {
        get => _currentDataVaultMasterPassword;
        set
        {
            if (SetProperty(ref _currentDataVaultMasterPassword, value))
            {
                ClearDataVaultPasswordFeedback();
                UpdateDataVaultPasswordCommandState();
            }
        }
    }

    public string NewDataVaultMasterPassword
    {
        get => _newDataVaultMasterPassword;
        set
        {
            if (SetProperty(ref _newDataVaultMasterPassword, value))
            {
                ClearDataVaultPasswordFeedback();
                UpdateDataVaultPasswordCommandState();
            }
        }
    }

    public string ConfirmDataVaultMasterPassword
    {
        get => _confirmDataVaultMasterPassword;
        set
        {
            if (SetProperty(ref _confirmDataVaultMasterPassword, value))
            {
                ClearDataVaultPasswordFeedback();
                UpdateDataVaultPasswordCommandState();
            }
        }
    }

    public string? ChangeDataVaultPasswordError
    {
        get => _changeDataVaultPasswordError;
        private set => SetProperty(ref _changeDataVaultPasswordError, value);
    }

    public string? ChangeDataVaultPasswordSuccess
    {
        get => _changeDataVaultPasswordSuccess;
        private set => SetProperty(ref _changeDataVaultPasswordSuccess, value);
    }

    public bool IsDataVaultPasswordChangeBusy
    {
        get => _isDataVaultPasswordChangeBusy;
        private set
        {
            if (SetProperty(ref _isDataVaultPasswordChangeBusy, value))
            {
                UpdateDataVaultPasswordCommandState();
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
        // Load master password states and biometric availability sequentially to avoid deadlocks
        _hasVaultMasterPassword = await _vaultService.HasMasterPasswordAsync(cancellationToken).ConfigureAwait(false);
        _hasDataVaultMasterPassword = await _dataVaultService.HasMasterPasswordAsync(cancellationToken).ConfigureAwait(false);
        
        // Refresh states sequentially
        await RefreshVaultStateAsync(cancellationToken).ConfigureAwait(false);
        await RefreshDataVaultStateAsync(cancellationToken).ConfigureAwait(false);
        await RefreshAuthenticatorStateAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RefreshVaultStateAsync(CancellationToken cancellationToken = default)
    {
        var unlocked = _vaultService.IsUnlocked;
        
        // Check biometric availability and key sequentially
        var canUseBiometric = await _biometricAuthenticationService.IsAvailableAsync(cancellationToken).ConfigureAwait(false);
        var hasBiometricKey = await _vaultService.HasBiometricKeyAsync(cancellationToken).ConfigureAwait(false);
        var biometricConfigured = canUseBiometric && hasBiometricKey;
        
        // Update master password state
        // Update master password state
        _hasVaultMasterPassword = await _vaultService.HasMasterPasswordAsync(cancellationToken).ConfigureAwait(false);

        // Always use MainThread.InvokeOnMainThreadAsync to ensure we're on the UI thread
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

    public async Task RefreshDataVaultStateAsync(CancellationToken cancellationToken = default)
    {
        var unlocked = _dataVaultService.IsUnlocked;
        
        // Check biometric availability and key sequentially
        var canUseBiometric = await _biometricAuthenticationService.IsAvailableAsync(cancellationToken).ConfigureAwait(false);
        var hasBiometricKey = await _dataVaultService.HasBiometricKeyAsync(cancellationToken).ConfigureAwait(false);
        var biometricConfigured = canUseBiometric && hasBiometricKey;
        
        // Update master password state
        // Update master password state
        _hasDataVaultMasterPassword = await _dataVaultService.HasMasterPasswordAsync(cancellationToken).ConfigureAwait(false);

        // Always use MainThread.InvokeOnMainThreadAsync to ensure we're on the UI thread
        await MainThread.InvokeOnMainThreadAsync(() =>
        {
            IsDataVaultUnlocked = unlocked;
            CanUseDataVaultBiometric = canUseBiometric;
            IsDataVaultBiometricConfigured = biometricConfigured;
            EnableDataVaultBiometric = biometricConfigured;

            if (!unlocked)
            {
                NewDataVaultMasterPassword = string.Empty;
                ConfirmDataVaultMasterPassword = string.Empty;
            }

            ClearDataVaultPasswordFeedback();
        }).ConfigureAwait(false);
    }

    public async Task RefreshAuthenticatorStateAsync(CancellationToken cancellationToken = default)
    {
        // Fetch state asynchronously on background thread
        var hasPassword = await _totpEncryptionService.HasPasswordAsync().ConfigureAwait(false);

        // Always use MainThread.InvokeOnMainThreadAsync to ensure we're on the UI thread
        await MainThread.InvokeOnMainThreadAsync(() =>
        {
            HasAuthenticatorPassword = hasPassword;

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

    public Task<byte[]> ExportWithFilePasswordAsync(string filePassword, CancellationToken cancellationToken = default)
        => _vaultService.ExportWithFilePasswordAsync(filePassword, cancellationToken);

    public Task ImportWithFilePasswordAsync(Stream stream, string filePassword, CancellationToken cancellationToken = default)
        => _vaultService.ImportWithFilePasswordAsync(stream, filePassword, cancellationToken);

    public Task<byte[]> ExportDataVaultWithFilePasswordAsync(string filePassword, CancellationToken cancellationToken = default)
        => _dataVaultService.ExportWithFilePasswordAsync(filePassword, cancellationToken);

    public Task ImportDataVaultWithFilePasswordAsync(Stream stream, string filePassword, CancellationToken cancellationToken = default)
        => _dataVaultService.ImportWithFilePasswordAsync(stream, filePassword, cancellationToken);

    public async Task<bool> UnlockVaultWithPasswordAsync(string password, CancellationToken cancellationToken = default)
    {
        if (_vaultService.IsUnlocked)
        {
            return true;
        }

        return await _vaultService.UnlockAsync(password, cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> UnlockDataVaultWithPasswordAsync(string password, CancellationToken cancellationToken = default)
    {
        if (_dataVaultService.IsUnlocked)
        {
            return true;
        }

        return await _dataVaultService.UnlockAsync(password, cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> UnlockAuthenticatorWithPasswordAsync(string password, CancellationToken cancellationToken = default)
    {
        if (_totpEncryptionService.IsUnlocked)
        {
            return true;
        }

        return await _totpEncryptionService.UnlockWithPasswordAsync(password).ConfigureAwait(false);
    }

    public bool IsAuthenticatorUnlocked => _totpEncryptionService.IsUnlocked;

    public bool IsPasswordVaultConfigured => _vaultService.IsUnlocked || _hasVaultMasterPassword;
    public bool IsDataVaultConfigured => _dataVaultService.IsUnlocked || _hasDataVaultMasterPassword;

    public void LockVault()
    {
        _vaultService.Lock();
        IsVaultUnlocked = false;
    }

    public void LockDataVault()
    {
        _dataVaultService.Lock();
        IsDataVaultUnlocked = false;
    }

    public void LockAuthenticator()
    {
        _totpEncryptionService.Lock();
    }

    public void LockAllVaults()
    {
        LockVault();
        LockDataVault();
        LockAuthenticator();
    }



    public Task RestoreBackupWithMergeAsync(Stream backupStream, CancellationToken cancellationToken = default)
        => _vaultService.RestoreBackupWithMergeAsync(backupStream, cancellationToken);

    public Task RestoreDataVaultBackupWithMergeAsync(Stream backupStream, CancellationToken cancellationToken = default)
        => _dataVaultService.RestoreBackupWithMergeAsync(backupStream, cancellationToken);

    public Task RestoreAuthenticatorBackupWithMergeAsync(Stream backupStream, CancellationToken cancellationToken = default)
        => _totpService.RestoreBackupWithMergeAsync(backupStream, cancellationToken);

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public async Task<byte[]> CreateFullBackupAsync(string filePassword, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePassword);

        var backup = new FullBackupDto
        {
            Version = 2,
            CreatedAt = DateTimeOffset.UtcNow
        };

        // Export Password Vault if unlocked
        if (_vaultService.IsUnlocked)
        {
            var vaultBackupBytes = await _vaultService.ExportWithFilePasswordAsync(filePassword, cancellationToken).ConfigureAwait(false);
            var vaultBackupJson = Encoding.UTF8.GetString(vaultBackupBytes);
            backup.PasswordVault = JsonSerializer.Deserialize<PortableBackupDto>(vaultBackupJson, _jsonOptions);
        }

        // Export Data Vault if unlocked
        if (_dataVaultService.IsUnlocked)
        {
            var dataVaultBackupBytes = await _dataVaultService.ExportWithFilePasswordAsync(filePassword, cancellationToken).ConfigureAwait(false);
            var dataVaultBackupJson = Encoding.UTF8.GetString(dataVaultBackupBytes);
            backup.DataVault = JsonSerializer.Deserialize<PortableBackupDto>(dataVaultBackupJson, _jsonOptions);
        }

        // Export Authenticator if unlocked (now uses encrypted format)
        if (_totpEncryptionService.IsUnlocked)
        {
            var authBackupBytes = await _totpService.ExportWithFilePasswordAsync(filePassword, cancellationToken).ConfigureAwait(false);
            var authBackupJson = Encoding.UTF8.GetString(authBackupBytes);
            backup.AuthenticatorEncrypted = JsonSerializer.Deserialize<PortableBackupDto>(authBackupJson, _jsonOptions);
        }

        var json = JsonSerializer.Serialize(backup, _jsonOptions);
        return Encoding.UTF8.GetBytes(json);
    }

    public async Task RestoreFullBackupAsync(Stream backupStream, string filePassword, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(backupStream);
        ArgumentException.ThrowIfNullOrWhiteSpace(filePassword);

        using var reader = new StreamReader(backupStream, Encoding.UTF8, leaveOpen: true);
        var json = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        var backup = JsonSerializer.Deserialize<FullBackupDto>(json, _jsonOptions)
                     ?? throw new InvalidOperationException("Ungültiges Backup-Format.");

        // Restore Password Vault if present and unlocked
        if (backup.PasswordVault is not null && _vaultService.IsUnlocked)
        {
            var vaultJson = JsonSerializer.Serialize(backup.PasswordVault, _jsonOptions);
            using var vaultStream = new MemoryStream(Encoding.UTF8.GetBytes(vaultJson));
            await _vaultService.ImportWithFilePasswordAsync(vaultStream, filePassword, cancellationToken).ConfigureAwait(false);
        }

        // Restore Data Vault if present and unlocked
        if (backup.DataVault is not null && _dataVaultService.IsUnlocked)
        {
            var dataVaultJson = JsonSerializer.Serialize(backup.DataVault, _jsonOptions);
            using var dataVaultStream = new MemoryStream(Encoding.UTF8.GetBytes(dataVaultJson));
            await _dataVaultService.ImportWithFilePasswordAsync(dataVaultStream, filePassword, cancellationToken).ConfigureAwait(false);
        }

        // Restore Authenticator if present and unlocked (prefer encrypted format)
        if (backup.AuthenticatorEncrypted is not null && _totpEncryptionService.IsUnlocked)
        {
            var authJson = JsonSerializer.Serialize(backup.AuthenticatorEncrypted, _jsonOptions);
            using var authStream = new MemoryStream(Encoding.UTF8.GetBytes(authJson));
            await _totpService.ImportWithFilePasswordAsync(authStream, filePassword, cancellationToken).ConfigureAwait(false);
        }
        // Fallback to old unencrypted format for backward compatibility
        else if (backup.Authenticator is not null && _totpEncryptionService.IsUnlocked)
        {
            var authJson = JsonSerializer.Serialize(backup.Authenticator, _jsonOptions);
            using var authStream = new MemoryStream(Encoding.UTF8.GetBytes(authJson));
            await _totpService.RestoreLegacyBackupAsync(authStream, cancellationToken).ConfigureAwait(false);
        }
    }


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

            // If vault is not unlocked, try to unlock with current password
            if (!IsVaultUnlocked)
            {
                if (string.IsNullOrWhiteSpace(CurrentMasterPassword))
                {
                    ChangePasswordError = "Bitte gib dein aktuelles Master-Passwort ein.";
                    return;
                }

                var unlocked = await _vaultService.UnlockAsync(CurrentMasterPassword).ConfigureAwait(false);
                if (!unlocked)
                {
                    ChangePasswordError = "Das aktuelle Passwort ist falsch.";
                    return;
                }

                await MainThread.InvokeOnMainThreadAsync(() => IsVaultUnlocked = true).ConfigureAwait(false);
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

            // Lock the vault after password change
            _vaultService.Lock();

            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                IsVaultUnlocked = false;
                CurrentMasterPassword = string.Empty;
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

              // If setting a new password (not changing existing one), we don't need to unlock old one
            if (await _totpEncryptionService.HasPasswordAsync().ConfigureAwait(false))
            {
                if (!await _totpEncryptionService.UnlockWithPasswordAsync(CurrentAuthenticatorPassword))
                {
                    ChangeAuthenticatorPasswordError = "Das aktuelle Passwort ist falsch.";
                    return;
                }

                await _totpEncryptionService.ChangePasswordAsync(CurrentAuthenticatorPassword, NewAuthenticatorPassword).ConfigureAwait(false);
            }
            else
            {
                await _totpEncryptionService.SetupPasswordAsync(NewAuthenticatorPassword).ConfigureAwait(false);
            }

            // Verify the setup worked
            if (!await _totpEncryptionService.UnlockWithPasswordAsync(NewAuthenticatorPassword).ConfigureAwait(false))
            {
                throw new InvalidOperationException("Neue Einrichtung konnte nicht verifiziert werden.");
            }

            await MainThread.InvokeOnMainThreadAsync(async () =>
            {
                HasAuthenticatorPassword = await _totpEncryptionService.HasPasswordAsync().ConfigureAwait(false);
                NewAuthenticatorPassword = string.Empty;
                ConfirmAuthenticatorPassword = string.Empty;
                CurrentAuthenticatorPassword = string.Empty;
                
                await ToastService.ShowAsync("Passwort erfolgreich geändert");
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

    private async Task ChangeDataVaultPasswordAsync()
    {
        if (IsDataVaultPasswordChangeBusy)
        {
            return;
        }

        try
        {
            IsDataVaultPasswordChangeBusy = true;
            ClearDataVaultPasswordFeedback();

            // If vault is not unlocked, try to unlock with current password
            if (!IsDataVaultUnlocked)
            {
                if (string.IsNullOrWhiteSpace(CurrentDataVaultMasterPassword))
                {
                    ChangeDataVaultPasswordError = "Bitte gib dein aktuelles Master-Passwort ein.";
                    return;
                }

                var unlocked = await _dataVaultService.UnlockAsync(CurrentDataVaultMasterPassword).ConfigureAwait(false);
                if (!unlocked)
                {
                    ChangeDataVaultPasswordError = "Das aktuelle Passwort ist falsch.";
                    return;
                }

                await MainThread.InvokeOnMainThreadAsync(() => IsDataVaultUnlocked = true).ConfigureAwait(false);
            }

            if (string.IsNullOrWhiteSpace(NewDataVaultMasterPassword))
            {
                ChangeDataVaultPasswordError = "Bitte gib ein neues Master-Passwort ein.";
                return;
            }

            if (!string.Equals(NewDataVaultMasterPassword, ConfirmDataVaultMasterPassword, StringComparison.Ordinal))
            {
                ChangeDataVaultPasswordError = "Die Passwörter stimmen nicht überein.";
                return;
            }

            await _dataVaultService.ChangeMasterPasswordAsync(NewDataVaultMasterPassword, EnableDataVaultBiometric && CanUseDataVaultBiometric).ConfigureAwait(false);

            // Lock the data vault after password change
            _dataVaultService.Lock();

            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                IsDataVaultUnlocked = false;
                CurrentDataVaultMasterPassword = string.Empty;
                NewDataVaultMasterPassword = string.Empty;
                ConfirmDataVaultMasterPassword = string.Empty;
                ChangeDataVaultPasswordSuccess = "Master-Passwort wurde aktualisiert.";
                IsDataVaultBiometricConfigured = EnableDataVaultBiometric && CanUseDataVaultBiometric;
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                ChangeDataVaultPasswordError = ex.Message;
                ChangeDataVaultPasswordSuccess = null;
            }).ConfigureAwait(false);
        }
        finally
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsDataVaultPasswordChangeBusy = false).ConfigureAwait(false);
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

    private void UpdateDataVaultPasswordCommandState()
    {
        if (_changeDataVaultPasswordCommand is not null)
        {
            MainThread.BeginInvokeOnMainThread(_changeDataVaultPasswordCommand.ChangeCanExecute);
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

    private void ClearDataVaultPasswordFeedback()
    {
        ChangeDataVaultPasswordError = null;
        ChangeDataVaultPasswordSuccess = null;
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

    public async Task ResetPasswordVaultAsync(CancellationToken cancellationToken = default)
    {
        await _vaultService.ResetVaultAsync(cancellationToken).ConfigureAwait(false);
        LockVault();
        _hasVaultMasterPassword = false;
        await RefreshVaultStateAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ResetDataVaultAsync(CancellationToken cancellationToken = default)
    {
        await _dataVaultService.ResetVaultAsync(cancellationToken).ConfigureAwait(false);
        LockDataVault();
        _hasDataVaultMasterPassword = false;
        await RefreshDataVaultStateAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ResetAuthenticatorAsync(CancellationToken cancellationToken = default)
    {
        await _totpService.ResetVaultAsync(cancellationToken).ConfigureAwait(false);
        LockAuthenticator();
        await RefreshAuthenticatorStateAsync(cancellationToken).ConfigureAwait(false);
    }
}
