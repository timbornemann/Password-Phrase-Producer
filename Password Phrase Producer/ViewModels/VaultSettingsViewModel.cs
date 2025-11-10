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
    private readonly Command _clearRemotePasswordCommand;
    private VaultSyncProviderDescriptor? _selectedSyncProvider;
    private bool _isSyncEnabled;
    private bool _isAutoSyncEnabled;
    private bool _isSyncBusy;
    private bool _isSyncSettingsDirty;
    private bool _isLoadingSyncSettings;
    private string _syncStatusMessage = "Synchronisation inaktiv.";
    private string _fileSyncPath = string.Empty;
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
    private string _remotePassword = string.Empty;
    private string _confirmRemotePassword = string.Empty;
    private bool _isRemotePasswordConfigured;
    private string? _remotePasswordError;
    private string? _remotePasswordSuccess;
    private bool _isRemotePasswordBusy;

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

        _clearRemotePasswordCommand = new Command(async () => await ClearRemotePasswordAsync(), () => !IsRemotePasswordBusy && IsRemotePasswordProviderSelected && IsRemotePasswordConfigured);
        ClearRemotePasswordCommand = _clearRemotePasswordCommand;

        _changePasswordCommand = new Command(async () => await ChangeMasterPasswordAsync(), () => !IsPasswordChangeBusy && IsVaultUnlocked);
        ChangePasswordCommand = _changePasswordCommand;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<VaultSyncProviderDescriptor> SyncProviders { get; }

    public ICommand SaveSyncSettingsCommand { get; }

    public ICommand SyncNowCommand { get; }

    public ICommand SelectGoogleDriveDocumentCommand { get; }

    public ICommand ClearGoogleDriveDocumentCommand { get; }

    public ICommand ClearRemotePasswordCommand { get; }

    public ICommand ChangePasswordCommand { get; }

    public string RemotePassword
    {
        get => _remotePassword;
        set
        {
            if (SetProperty(ref _remotePassword, value))
            {
                if (!string.IsNullOrEmpty(RemotePasswordError))
                {
                    RemotePasswordError = null;
                }

                if (!string.IsNullOrEmpty(RemotePasswordSuccess))
                {
                    RemotePasswordSuccess = null;
                }

                if (!_isLoadingSyncSettings)
                {
                    MarkSyncSettingsDirty();
                }
            }
        }
    }

    public string ConfirmRemotePassword
    {
        get => _confirmRemotePassword;
        set
        {
            if (SetProperty(ref _confirmRemotePassword, value))
            {
                if (!string.IsNullOrEmpty(RemotePasswordError))
                {
                    RemotePasswordError = null;
                }

                if (!string.IsNullOrEmpty(RemotePasswordSuccess))
                {
                    RemotePasswordSuccess = null;
                }

                if (!_isLoadingSyncSettings)
                {
                    MarkSyncSettingsDirty();
                }
            }
        }
    }

    public bool IsRemotePasswordConfigured
    {
        get => _isRemotePasswordConfigured;
        private set
        {
            if (SetProperty(ref _isRemotePasswordConfigured, value))
            {
                UpdateRemotePasswordCommandStates();
            }
        }
    }

    public string? RemotePasswordError
    {
        get => _remotePasswordError;
        private set => SetProperty(ref _remotePasswordError, value);
    }

    public string? RemotePasswordSuccess
    {
        get => _remotePasswordSuccess;
        private set => SetProperty(ref _remotePasswordSuccess, value);
    }

    public bool IsRemotePasswordBusy
    {
        get => _isRemotePasswordBusy;
        private set
        {
            if (SetProperty(ref _isRemotePasswordBusy, value))
            {
                UpdateRemotePasswordCommandStates();
            }
        }
    }

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
            if (SetProperty(ref _selectedSyncProvider, value))
            {
                OnPropertyChanged(nameof(IsFileProviderSelected));
                OnPropertyChanged(nameof(IsGoogleDriveProviderSelected));
                OnPropertyChanged(nameof(IsRemotePasswordProviderSelected));
                OnPropertyChanged(nameof(IsRemotePasswordRequired));

                if (!_isLoadingSyncSettings)
                {
                    MarkSyncSettingsDirty();
                }

                UpdateSyncCommandStates();
                _ = RefreshRemotePasswordStateAsync();
            }
        }
    }

    public bool IsFileProviderSelected => string.Equals(SelectedSyncProvider?.Key, FileSystemVaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase);

    public bool IsGoogleDriveProviderSelected => string.Equals(SelectedSyncProvider?.Key, GoogleDriveVaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase);

    public bool IsRemotePasswordProviderSelected => RequiresRemotePassword(SelectedSyncProvider?.Key);

    public bool IsRemotePasswordRequired => IsRemotePasswordProviderSelected;

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
            configuration.Parameters.TryGetValue(GoogleDriveVaultSyncProvider.DocumentUriParameterKey, out var googleDocumentUri);

            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                SelectedSyncProvider = providers.FirstOrDefault(p => string.Equals(p.Key, configuration.ProviderKey, StringComparison.OrdinalIgnoreCase));
                IsSyncEnabled = configuration.IsEnabled;
                IsAutoSyncEnabled = configuration.AutoSyncEnabled;
                FileSyncPath = path ?? string.Empty;
                GoogleDriveDocumentUri = googleDocumentUri ?? string.Empty;
                IsRemotePasswordConfigured = false;
                RemotePassword = string.Empty;
                ConfirmRemotePassword = string.Empty;
                RemotePasswordError = null;
                RemotePasswordSuccess = null;
                UpdateSyncStatusMessage(status, null);
                IsSyncSettingsDirty = false;
            }).ConfigureAwait(false);
        }
        finally
        {
            _isLoadingSyncSettings = false;
        }

        await RefreshRemotePasswordStateAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task SaveSyncSettingsAsync()
    {
        try
        {
            var configuration = BuildSyncConfiguration();
            var providerKey = configuration.ProviderKey;

            try
            {
                await ApplyRemotePasswordUpdatesAsync(providerKey).ConfigureAwait(false);
                await EnsureRemotePasswordConfiguredAsync(providerKey).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await MainThread.InvokeOnMainThreadAsync(() =>
                {
                    RemotePasswordSuccess = null;
                    RemotePasswordError = ex.Message;
                }).ConfigureAwait(false);
                throw;
            }

            await _vaultService.UpdateSyncConfigurationAsync(configuration).ConfigureAwait(false);
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                var previousLoading = _isLoadingSyncSettings;
                _isLoadingSyncSettings = true;
                IsSyncSettingsDirty = false;
                if (IsRemotePasswordRequired)
                {
                    RemotePassword = string.Empty;
                    ConfirmRemotePassword = string.Empty;
                }
                _isLoadingSyncSettings = previousLoading;
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
            string? uri = null;
            var page = Application.Current?.MainPage;

            if (page is not null)
            {
                var createOption = "Neue Tresordatei erstellen";
                var pickOption = "Bestehende Datei auswählen";
                var choice = await MainThread.InvokeOnMainThreadAsync(() => page.DisplayActionSheet("Google Drive Datei", "Abbrechen", null, createOption, pickOption)).ConfigureAwait(false);

                if (string.Equals(choice, createOption, StringComparison.Ordinal))
                {
                    uri = await _googleDriveDocumentPicker.CreateDocumentAsync(GoogleDriveVaultSyncProvider.DefaultFileName).ConfigureAwait(false);
                }
                else if (string.Equals(choice, pickOption, StringComparison.Ordinal))
                {
                    uri = await _googleDriveDocumentPicker.PickExistingDocumentAsync().ConfigureAwait(false);
                }
                else
                {
                    return;
                }
            }
            else
            {
                uri = await _googleDriveDocumentPicker.CreateDocumentAsync(GoogleDriveVaultSyncProvider.DefaultFileName).ConfigureAwait(false);
            }

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

    private async Task<bool> ApplyRemotePasswordUpdatesAsync(string? providerKey)
    {
        if (!RequiresRemotePassword(providerKey))
        {
            return false;
        }

        var password = RemotePassword?.Trim();
        var confirm = ConfirmRemotePassword?.Trim();

        if (string.IsNullOrEmpty(password) && string.IsNullOrEmpty(confirm))
        {
            return false;
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new InvalidOperationException("Bitte gib ein Remote-Passwort ein.");
        }

        if (!string.Equals(password, confirm, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Die Remote-Passwörter stimmen nicht überein.");
        }

        if (string.IsNullOrWhiteSpace(providerKey))
        {
            throw new InvalidOperationException("Bitte wähle einen Synchronisationsanbieter aus.");
        }

        await _vaultService.SetRemotePasswordAsync(providerKey, password).ConfigureAwait(false);

        await MainThread.InvokeOnMainThreadAsync(() =>
        {
            RemotePassword = string.Empty;
            ConfirmRemotePassword = string.Empty;
            RemotePasswordError = null;
            RemotePasswordSuccess = "Das Remote-Passwort wurde gespeichert.";
            IsRemotePasswordConfigured = true;
        }).ConfigureAwait(false);

        return true;
    }

    private async Task EnsureRemotePasswordConfiguredAsync(string? providerKey, CancellationToken cancellationToken = default)
    {
        if (!RequiresRemotePassword(providerKey))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(providerKey))
        {
            throw new InvalidOperationException("Bitte wähle einen Synchronisationsanbieter aus.");
        }

        var hasRemotePassword = await _vaultService.HasRemotePasswordAsync(providerKey, cancellationToken).ConfigureAwait(false);
        if (!hasRemotePassword)
        {
            throw new InvalidOperationException("Bitte vergebe ein Remote-Passwort für die Synchronisation.");
        }

        await MainThread.InvokeOnMainThreadAsync(() =>
        {
            IsRemotePasswordConfigured = true;
        }).ConfigureAwait(false);
    }

    private async Task RefreshRemotePasswordStateAsync(CancellationToken cancellationToken = default)
    {
        var providerKey = SelectedSyncProvider?.Key;
        if (!RequiresRemotePassword(providerKey))
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                IsRemotePasswordConfigured = false;
                RemotePassword = string.Empty;
                ConfirmRemotePassword = string.Empty;
                RemotePasswordError = null;
                RemotePasswordSuccess = null;
            }).ConfigureAwait(false);
            return;
        }

        if (string.IsNullOrWhiteSpace(providerKey))
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                IsRemotePasswordConfigured = false;
                RemotePasswordSuccess = null;
            }).ConfigureAwait(false);
            return;
        }

        var hasRemotePassword = await _vaultService.HasRemotePasswordAsync(providerKey, cancellationToken).ConfigureAwait(false);

        await MainThread.InvokeOnMainThreadAsync(() =>
        {
            IsRemotePasswordConfigured = hasRemotePassword;
            if (!hasRemotePassword)
            {
                RemotePasswordSuccess = null;
            }
        }).ConfigureAwait(false);
    }

    private async Task ClearRemotePasswordAsync()
    {
        var providerKey = SelectedSyncProvider?.Key;
        if (!RequiresRemotePassword(providerKey) || !IsRemotePasswordConfigured || IsRemotePasswordBusy)
        {
            return;
        }

        var key = providerKey!;

        try
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsRemotePasswordBusy = true).ConfigureAwait(false);
            await _vaultService.ClearRemotePasswordAsync(key).ConfigureAwait(false);
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                IsRemotePasswordConfigured = false;
                RemotePassword = string.Empty;
                ConfirmRemotePassword = string.Empty;
                RemotePasswordError = null;
                RemotePasswordSuccess = "Das Remote-Passwort wurde entfernt.";
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                RemotePasswordSuccess = null;
                RemotePasswordError = $"Fehler beim Entfernen des Remote-Passworts: {ex.Message}";
            }).ConfigureAwait(false);
        }
        finally
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsRemotePasswordBusy = false).ConfigureAwait(false);
        }
    }

    private static bool RequiresRemotePassword(string? providerKey)
        => string.Equals(providerKey, GoogleDriveVaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase)
            || string.Equals(providerKey, FileSystemVaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase);

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
        UpdateRemotePasswordCommandStates();
    }

    private void UpdatePasswordCommandState()
        => MainThread.BeginInvokeOnMainThread(_changePasswordCommand.ChangeCanExecute);

    private void UpdateRemotePasswordCommandStates()
        => MainThread.BeginInvokeOnMainThread(_clearRemotePasswordCommand.ChangeCanExecute);

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
