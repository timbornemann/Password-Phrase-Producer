using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Vault;
using Password_Phrase_Producer.Services.Vault.Sync;

namespace Password_Phrase_Producer.ViewModels;

public class VaultSettingsViewModel : INotifyPropertyChanged
{
    private readonly PasswordVaultService _vaultService;
    private readonly IBiometricAuthenticationService _biometricAuthenticationService;
    private readonly IGoogleDriveDocumentPicker _googleDriveDocumentPicker;
    private readonly ObservableCollection<VaultSyncProviderDescriptor> _syncProviders = new();
    private readonly Command _selectGoogleDriveDocumentCommand;
    private readonly Command _clearGoogleDriveDocumentCommand;
    private readonly Command _changePasswordCommand;
    private VaultSyncProviderDescriptor? _selectedSyncProvider;
    private bool _isSyncEnabled;
    private bool _isAutoSyncEnabled;
    private bool _isSyncBusy;
    private bool _isSyncSettingsDirty;
    private bool _isLoadingSyncSettings;
    private string _syncStatusMessage = "Synchronisation inaktiv.";
    private string _fileSyncPath = string.Empty;
    private string _s3BucketName = string.Empty;
    private string _s3ObjectKey = "vault.json.enc";
    private string _s3Region = string.Empty;
    private string _s3AccessKeyId = string.Empty;
    private string _s3SecretAccessKey = string.Empty;
    private string? _currentS3Secret;
    private bool _hasS3Secret;
    private string _googleDriveDocumentUri = string.Empty;
    private DateTimeOffset? _lastSyncUtc;
    private VaultSyncOperation _lastSyncOperation = VaultSyncOperation.None;
    private string? _lastSyncError;
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
        IBiometricAuthenticationService biometricAuthenticationService,
        IGoogleDriveDocumentPicker googleDriveDocumentPicker)
    {
        _vaultService = vaultService;
        _biometricAuthenticationService = biometricAuthenticationService;
        _googleDriveDocumentPicker = googleDriveDocumentPicker;
        SyncProviders = _syncProviders;

        SaveSyncSettingsCommand = new Command(async () => await SaveSyncSettingsAsync(), () => IsSyncSettingsDirty && !IsSyncBusy);
        SyncNowCommand = new Command(async () => await SyncNowAsync(), () => !IsSyncBusy && IsSyncEnabled);
        _selectGoogleDriveDocumentCommand = new Command(async () => await SelectGoogleDriveDocumentAsync(), () => !IsSyncBusy && IsGoogleDriveProviderSelected);
        _clearGoogleDriveDocumentCommand = new Command(ClearGoogleDriveDocumentSelection, () => !IsSyncBusy && IsGoogleDriveProviderSelected && !string.IsNullOrWhiteSpace(GoogleDriveDocumentUri));
        SelectGoogleDriveDocumentCommand = _selectGoogleDriveDocumentCommand;
        ClearGoogleDriveDocumentCommand = _clearGoogleDriveDocumentCommand;

        _changePasswordCommand = new Command(async () => await ChangeMasterPasswordAsync(), () => !IsPasswordChangeBusy && IsVaultUnlocked);
        ChangePasswordCommand = _changePasswordCommand;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<VaultSyncProviderDescriptor> SyncProviders { get; }

    public ICommand SaveSyncSettingsCommand { get; }

    public ICommand SyncNowCommand { get; }

    public ICommand SelectGoogleDriveDocumentCommand { get; }

    public ICommand ClearGoogleDriveDocumentCommand { get; }

    public ICommand ChangePasswordCommand { get; }

    public bool IsSyncEnabled
    {
        get => _isSyncEnabled;
        set
        {
            if (SetProperty(ref _isSyncEnabled, value) && !_isLoadingSyncSettings)
            {
                MarkSyncSettingsDirty();
                UpdateSyncCommandStates();
            }
        }
    }

    public bool IsAutoSyncEnabled
    {
        get => _isAutoSyncEnabled;
        set
        {
            if (SetProperty(ref _isAutoSyncEnabled, value) && !_isLoadingSyncSettings)
            {
                MarkSyncSettingsDirty();
                UpdateSyncCommandStates();
            }
        }
    }

    public bool IsSyncBusy
    {
        get => _isSyncBusy;
        private set
        {
            if (SetProperty(ref _isSyncBusy, value))
            {
                UpdateSyncCommandStates();
            }
        }
    }

    public bool IsSyncSettingsDirty
    {
        get => _isSyncSettingsDirty;
        private set
        {
            if (SetProperty(ref _isSyncSettingsDirty, value))
            {
                UpdateSyncCommandStates();
            }
        }
    }

    public VaultSyncProviderDescriptor? SelectedSyncProvider
    {
        get => _selectedSyncProvider;
        set
        {
            if (SetProperty(ref _selectedSyncProvider, value) && !_isLoadingSyncSettings)
            {
                MarkSyncSettingsDirty();
                OnPropertyChanged(nameof(IsS3ProviderSelected));
                OnPropertyChanged(nameof(IsFileProviderSelected));
                OnPropertyChanged(nameof(IsGoogleDriveProviderSelected));
                UpdateSyncCommandStates();
            }
        }
    }

    public bool IsS3ProviderSelected => string.Equals(SelectedSyncProvider?.Key, S3VaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase);

    public bool IsFileProviderSelected => string.Equals(SelectedSyncProvider?.Key, FileSystemVaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase);

    public bool IsGoogleDriveProviderSelected => string.Equals(SelectedSyncProvider?.Key, GoogleDriveVaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase);

    public string FileSyncPath
    {
        get => _fileSyncPath;
        set
        {
            if (SetProperty(ref _fileSyncPath, value) && !_isLoadingSyncSettings)
            {
                MarkSyncSettingsDirty();
            }
        }
    }

    public string S3BucketName
    {
        get => _s3BucketName;
        set
        {
            if (SetProperty(ref _s3BucketName, value) && !_isLoadingSyncSettings)
            {
                MarkSyncSettingsDirty();
            }
        }
    }

    public string S3ObjectKey
    {
        get => _s3ObjectKey;
        set
        {
            if (SetProperty(ref _s3ObjectKey, value) && !_isLoadingSyncSettings)
            {
                MarkSyncSettingsDirty();
            }
        }
    }

    public string S3Region
    {
        get => _s3Region;
        set
        {
            if (SetProperty(ref _s3Region, value) && !_isLoadingSyncSettings)
            {
                MarkSyncSettingsDirty();
            }
        }
    }

    public string S3AccessKeyId
    {
        get => _s3AccessKeyId;
        set
        {
            if (SetProperty(ref _s3AccessKeyId, value) && !_isLoadingSyncSettings)
            {
                MarkSyncSettingsDirty();
            }
        }
    }

    public string S3SecretAccessKey
    {
        get => _s3SecretAccessKey;
        set
        {
            if (SetProperty(ref _s3SecretAccessKey, value) && !_isLoadingSyncSettings)
            {
                MarkSyncSettingsDirty();
            }
        }
    }

    public bool HasS3Secret
    {
        get => _hasS3Secret;
        private set => SetProperty(ref _hasS3Secret, value);
    }

    public string GoogleDriveDocumentUri
    {
        get => _googleDriveDocumentUri;
        set
        {
            if (SetProperty(ref _googleDriveDocumentUri, value))
            {
                if (!_isLoadingSyncSettings)
                {
                    MarkSyncSettingsDirty();
                }

                UpdateSyncCommandStates();
            }
        }
    }

    public DateTimeOffset? LastSyncUtc
    {
        get => _lastSyncUtc;
        private set => SetProperty(ref _lastSyncUtc, value);
    }

    public string SyncStatusMessage
    {
        get => _syncStatusMessage;
        private set => SetProperty(ref _syncStatusMessage, value);
    }

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
        private set => SetProperty(ref _canUseBiometric, value);
    }

    public bool IsBiometricConfigured
    {
        get => _isBiometricConfigured;
        private set => SetProperty(ref _isBiometricConfigured, value);
    }

    public bool EnableBiometric
    {
        get => _enableBiometric;
        set => SetProperty(ref _enableBiometric, value);
    }

    public string NewMasterPassword
    {
        get => _newMasterPassword;
        set
        {
            if (SetProperty(ref _newMasterPassword, value))
            {
                if (!string.IsNullOrEmpty(ChangePasswordError))
                {
                    ChangePasswordError = null;
                }

                if (!string.IsNullOrEmpty(ChangePasswordSuccess))
                {
                    ChangePasswordSuccess = null;
                }
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
                if (!string.IsNullOrEmpty(ChangePasswordError))
                {
                    ChangePasswordError = null;
                }

                if (!string.IsNullOrEmpty(ChangePasswordSuccess))
                {
                    ChangePasswordSuccess = null;
                }
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

        MessagingCenter.Subscribe<PasswordVaultService, VaultSyncResult>(this, VaultMessages.SyncStatusChanged, OnSyncStatusChanged);
        _isListening = true;
    }

    public void Deactivate()
    {
        if (!_isListening)
        {
            return;
        }

        MessagingCenter.Unsubscribe<PasswordVaultService, VaultSyncResult>(this, VaultMessages.SyncStatusChanged);
        _isListening = false;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await LoadSyncConfigurationAsync(cancellationToken).ConfigureAwait(false);
        await RefreshVaultStateAsync(cancellationToken).ConfigureAwait(false);
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

            ChangePasswordError = null;
            ChangePasswordSuccess = null;
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

    private async Task LoadSyncConfigurationAsync(CancellationToken cancellationToken = default)
    {
        _isLoadingSyncSettings = true;
        try
        {
            var providers = _vaultService.GetAvailableSyncProviders().ToList();
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                _syncProviders.Clear();
                foreach (var provider in providers)
                {
                    _syncProviders.Add(provider);
                }
            }).ConfigureAwait(false);

            var configuration = await _vaultService.GetSyncConfigurationAsync(cancellationToken).ConfigureAwait(false);
            var status = await _vaultService.GetSyncStatusAsync(cancellationToken).ConfigureAwait(false);

            configuration.Parameters.TryGetValue(FileSystemVaultSyncProvider.PathParameterKey, out var path);
            configuration.Parameters.TryGetValue(S3VaultSyncProvider.BucketParameterKey, out var bucket);
            configuration.Parameters.TryGetValue(S3VaultSyncProvider.ObjectKeyParameterKey, out var objectKey);
            configuration.Parameters.TryGetValue(S3VaultSyncProvider.RegionParameterKey, out var region);
            configuration.Parameters.TryGetValue(S3VaultSyncProvider.AccessKeyIdParameterKey, out var accessKeyId);
            configuration.Parameters.TryGetValue(S3VaultSyncProvider.SecretAccessKeyParameterKey, out var secret);
            configuration.Parameters.TryGetValue(GoogleDriveVaultSyncProvider.DocumentUriParameterKey, out var googleDocumentUri);

            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                SelectedSyncProvider = providers.FirstOrDefault(p => string.Equals(p.Key, configuration.ProviderKey, StringComparison.OrdinalIgnoreCase));
                IsSyncEnabled = configuration.IsEnabled;
                IsAutoSyncEnabled = configuration.AutoSyncEnabled;
                FileSyncPath = path ?? string.Empty;
                S3BucketName = bucket ?? string.Empty;
                S3ObjectKey = string.IsNullOrWhiteSpace(objectKey) ? "vault.json.enc" : objectKey;
                S3Region = region ?? string.Empty;
                S3AccessKeyId = accessKeyId ?? string.Empty;
                _currentS3Secret = secret;
                HasS3Secret = !string.IsNullOrWhiteSpace(_currentS3Secret);
                S3SecretAccessKey = string.Empty;
                GoogleDriveDocumentUri = googleDocumentUri ?? string.Empty;
                UpdateSyncStatusMessage(status, null);
                IsSyncSettingsDirty = false;
            }).ConfigureAwait(false);
        }
        finally
        {
            _isLoadingSyncSettings = false;
        }
    }

    private async Task SaveSyncSettingsAsync()
    {
        try
        {
            var configuration = BuildSyncConfiguration();
            await _vaultService.UpdateSyncConfigurationAsync(configuration).ConfigureAwait(false);
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                _currentS3Secret = configuration.Parameters.TryGetValue(S3VaultSyncProvider.SecretAccessKeyParameterKey, out var secret)
                    ? secret
                    : null;
                HasS3Secret = !string.IsNullOrWhiteSpace(_currentS3Secret);
                S3SecretAccessKey = string.Empty;
                IsSyncSettingsDirty = false;
            }).ConfigureAwait(false);
            await RefreshSyncStatusAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                SyncStatusMessage = $"Fehler beim Speichern der Synchronisation: {ex.Message}";
            }).ConfigureAwait(false);
        }
    }

    private async Task SyncNowAsync()
    {
        if (IsSyncBusy)
        {
            return;
        }

        try
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsSyncBusy = true).ConfigureAwait(false);
            var result = await _vaultService.SynchronizeAsync().ConfigureAwait(false);
            await RefreshSyncStatusAsync(result).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                SyncStatusMessage = $"Fehler bei der Synchronisation: {ex.Message}";
            }).ConfigureAwait(false);
        }
        finally
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsSyncBusy = false).ConfigureAwait(false);
        }
    }

    private VaultSyncConfiguration BuildSyncConfiguration()
    {
        var configuration = new VaultSyncConfiguration
        {
            IsEnabled = IsSyncEnabled,
            AutoSyncEnabled = IsAutoSyncEnabled,
            ProviderKey = SelectedSyncProvider?.Key
        };

        if (IsFileProviderSelected && !string.IsNullOrWhiteSpace(FileSyncPath))
        {
            configuration.Parameters[FileSystemVaultSyncProvider.PathParameterKey] = FileSyncPath.Trim();
        }

        if (IsS3ProviderSelected)
        {
            if (!string.IsNullOrWhiteSpace(S3BucketName))
            {
                configuration.Parameters[S3VaultSyncProvider.BucketParameterKey] = S3BucketName.Trim();
            }

            configuration.Parameters[S3VaultSyncProvider.ObjectKeyParameterKey] = string.IsNullOrWhiteSpace(S3ObjectKey)
                ? "vault.json.enc"
                : S3ObjectKey.Trim();

            if (!string.IsNullOrWhiteSpace(S3Region))
            {
                configuration.Parameters[S3VaultSyncProvider.RegionParameterKey] = S3Region.Trim();
            }

            if (!string.IsNullOrWhiteSpace(S3AccessKeyId))
            {
                configuration.Parameters[S3VaultSyncProvider.AccessKeyIdParameterKey] = S3AccessKeyId.Trim();
            }

            if (!string.IsNullOrWhiteSpace(S3SecretAccessKey))
            {
                configuration.Parameters[S3VaultSyncProvider.SecretAccessKeyParameterKey] = S3SecretAccessKey;
            }
            else if (!string.IsNullOrWhiteSpace(_currentS3Secret))
            {
                configuration.Parameters[S3VaultSyncProvider.SecretAccessKeyParameterKey] = _currentS3Secret!;
            }
        }

        if (IsGoogleDriveProviderSelected && !string.IsNullOrWhiteSpace(GoogleDriveDocumentUri))
        {
            configuration.Parameters[GoogleDriveVaultSyncProvider.DocumentUriParameterKey] = GoogleDriveDocumentUri.Trim();
        }

        return configuration;
    }

    private async Task RefreshSyncStatusAsync(VaultSyncResult? result = null, CancellationToken cancellationToken = default)
    {
        var status = await _vaultService.GetSyncStatusAsync(cancellationToken).ConfigureAwait(false);
        await MainThread.InvokeOnMainThreadAsync(() => UpdateSyncStatusMessage(status, result)).ConfigureAwait(false);
    }

    private async Task SelectGoogleDriveDocumentAsync()
    {
        if (!IsGoogleDriveProviderSelected)
        {
            return;
        }

        try
        {
            var uri = await _googleDriveDocumentPicker.CreateDocumentAsync(GoogleDriveVaultSyncProvider.DefaultFileName).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(uri))
            {
                GoogleDriveDocumentUri = uri!;
            }
        }
        catch (TaskCanceledException)
        {
            // Auswahl wurde abgebrochen – nichts weiter zu tun.
        }
        catch (Exception ex)
        {
            await MainThread.InvokeOnMainThreadAsync(async () =>
            {
                var page = Application.Current?.MainPage;
                if (page is not null)
                {
                    await page.DisplayAlert("Google Drive", ex.Message, "OK");
                }
            }).ConfigureAwait(false);
        }
    }

    private void ClearGoogleDriveDocumentSelection()
    {
        if (string.IsNullOrWhiteSpace(GoogleDriveDocumentUri))
        {
            return;
        }

        try
        {
            _googleDriveDocumentPicker.ReleasePersistedPermission(GoogleDriveDocumentUri);
        }
        catch (Exception)
        {
            // Einige Provider unterstützen keine persistente Berechtigung – ignorieren.
        }

        GoogleDriveDocumentUri = string.Empty;
    }

    private async Task ChangeMasterPasswordAsync()
    {
        if (!IsVaultUnlocked)
        {
            ChangePasswordSuccess = null;
            ChangePasswordError = "Der Tresor ist gesperrt. Bitte entsperre ihn zuerst.";
            return;
        }

        var password = NewMasterPassword?.Trim();
        var confirm = ConfirmMasterPassword?.Trim();

        if (string.IsNullOrWhiteSpace(password))
        {
            ChangePasswordSuccess = null;
            ChangePasswordError = "Bitte gib ein neues Master-Passwort ein.";
            return;
        }

        if (!string.Equals(password, confirm, StringComparison.Ordinal))
        {
            ChangePasswordSuccess = null;
            ChangePasswordError = "Die Passwörter stimmen nicht überein.";
            return;
        }

        try
        {
            ChangePasswordError = null;
            ChangePasswordSuccess = null;
            IsPasswordChangeBusy = true;

            await _vaultService.ChangeMasterPasswordAsync(password, EnableBiometric && CanUseBiometric).ConfigureAwait(false);

            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                NewMasterPassword = string.Empty;
                ConfirmMasterPassword = string.Empty;
                ChangePasswordSuccess = "Das Master-Passwort wurde aktualisiert.";
                IsBiometricConfigured = EnableBiometric && CanUseBiometric;
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                ChangePasswordSuccess = null;
                ChangePasswordError = $"Fehler beim Ändern des Master-Passworts: {ex.Message}";
            }).ConfigureAwait(false);
        }
        finally
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                IsPasswordChangeBusy = false;
            }).ConfigureAwait(false);
        }
    }

    private void OnSyncStatusChanged(PasswordVaultService sender, VaultSyncResult result)
    {
        _ = RefreshSyncStatusAsync(result).ContinueWith(task =>
        {
            if (task.Exception is not null)
            {
                System.Diagnostics.Debug.WriteLine($"Fehler beim Aktualisieren des Sync-Status: {task.Exception}");
            }
        }, TaskScheduler.Default);
    }

    private void UpdateSyncStatusMessage(VaultSyncStatus status, VaultSyncResult? result)
    {
        LastSyncUtc = status.LastSyncUtc;
        _lastSyncOperation = status.LastOperation;
        _lastSyncError = result?.ErrorMessage ?? status.LastError;

        var builder = new StringBuilder();
        builder.Append("Status: ").Append(DescribeSyncOperation(status.LastOperation));

        if (status.LastSyncUtc is DateTimeOffset lastSync)
        {
            builder.Append(" • Letzte Synchronisation: ").Append(lastSync.ToLocalTime().ToString("g"));
        }

        var error = result?.ErrorMessage ?? status.LastError;
        if (!string.IsNullOrWhiteSpace(error))
        {
            builder.Append(" • Fehler: ").Append(error);
        }
        else if (status.RemoteState is { } remote)
        {
            builder.Append(" • Remote-Stand: ").Append(remote.LastModifiedUtc.ToLocalTime().ToString("g"));
        }

        SyncStatusMessage = builder.ToString();
    }

    private static string DescribeSyncOperation(VaultSyncOperation operation)
        => operation switch
        {
            VaultSyncOperation.None => "Keine Synchronisation",
            VaultSyncOperation.Disabled => "Deaktiviert",
            VaultSyncOperation.NoProvider => "Kein Anbieter",
            VaultSyncOperation.UpToDate => "Aktuell",
            VaultSyncOperation.Uploaded => "Hochgeladen",
            VaultSyncOperation.Downloaded => "Heruntergeladen",
            VaultSyncOperation.Conflict => "Konflikt",
            VaultSyncOperation.Error => "Fehler",
            _ => "Unbekannt"
        };

    private void MarkSyncSettingsDirty()
    {
        if (_isLoadingSyncSettings)
        {
            return;
        }

        IsSyncSettingsDirty = true;
    }

    private void UpdateSyncCommandStates()
    {
        if (SaveSyncSettingsCommand is Command saveCommand)
        {
            MainThread.BeginInvokeOnMainThread(saveCommand.ChangeCanExecute);
        }

        if (SyncNowCommand is Command syncCommand)
        {
            MainThread.BeginInvokeOnMainThread(syncCommand.ChangeCanExecute);
        }

        MainThread.BeginInvokeOnMainThread(_selectGoogleDriveDocumentCommand.ChangeCanExecute);
        MainThread.BeginInvokeOnMainThread(_clearGoogleDriveDocumentCommand.ChangeCanExecute);
    }

    private void UpdatePasswordCommandState()
        => MainThread.BeginInvokeOnMainThread(_changePasswordCommand.ChangeCanExecute);

    private bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
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
