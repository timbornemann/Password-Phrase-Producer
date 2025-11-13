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
    private readonly Command _editSyncSettingsCommand;
    private readonly Command _cancelSyncSettingsCommand;
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
    private bool _isSyncConfigured;
    private bool _isEditingSyncSettings = true;
    private string _syncSummaryProviderName = "Keine Verbindung aktiviert";
    private string _syncSummaryConnectionDetail = "Wähle einen Synchronisationsanbieter, um zu starten.";
    private string _syncSummaryLastSync = "Noch keine Synchronisation durchgeführt.";
    private string _syncSummaryNextSync = "Automatische Synchronisation deaktiviert.";
    private string _syncSummaryRemoteInfo = "Cloud-Datei wurde noch nicht erstellt.";

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
    private bool _hasExistingRemoteVault;
    private CancellationTokenSource? _remoteStateRefreshCts;

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

        _editSyncSettingsCommand = new Command(EnterSyncEditMode, () => IsSyncConfigured && !IsEditingSyncSettings);
        EditSyncSettingsCommand = _editSyncSettingsCommand;

        _cancelSyncSettingsCommand = new Command(async () => await CancelSyncEditingAsync(), () => IsSyncConfigured && IsEditingSyncSettings && !IsSyncBusy);
        CancelSyncSettingsCommand = _cancelSyncSettingsCommand;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<VaultSyncProviderDescriptor> SyncProviders { get; }

    public ICommand SaveSyncSettingsCommand { get; }

    public ICommand SyncNowCommand { get; }

    public ICommand SelectGoogleDriveDocumentCommand { get; }

    public ICommand ClearGoogleDriveDocumentCommand { get; }

    public ICommand ClearRemotePasswordCommand { get; }

    public ICommand ChangePasswordCommand { get; }

    public ICommand EditSyncSettingsCommand { get; }

    public ICommand CancelSyncSettingsCommand { get; }

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
                EvaluateSyncConfigurationState(false);
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

    public bool HasExistingRemoteVault
    {
        get => _hasExistingRemoteVault;
        private set
        {
            if (SetProperty(ref _hasExistingRemoteVault, value))
            {
                OnPropertyChanged(nameof(IsRemotePasswordConfirmationVisible));
            }
        }
    }

    public bool IsRemotePasswordConfirmationVisible => IsRemotePasswordRequired && !HasExistingRemoteVault;

    public bool IsSyncEnabled
    {
        get => _isSyncEnabled;
        set
        {
            if (SetProperty(ref _isSyncEnabled, value))
            {
                if (!_isLoadingSyncSettings)
                {
                    MarkSyncSettingsDirty();
                }

                UpdateSyncCommandStates();
                EvaluateSyncConfigurationState(false);
            }
        }
    }

    public bool IsAutoSyncEnabled
    {
        get => _isAutoSyncEnabled;
        set
        {
            if (SetProperty(ref _isAutoSyncEnabled, value))
            {
                if (!_isLoadingSyncSettings)
                {
                    MarkSyncSettingsDirty();
                }

                UpdateSyncCommandStates();
                EvaluateSyncConfigurationState(false);
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
                OnPropertyChanged(nameof(IsRemotePasswordConfirmationVisible));

                if (!_isLoadingSyncSettings)
                {
                    MarkSyncSettingsDirty();
                }

                UpdateSyncCommandStates();
                EvaluateSyncConfigurationState(false);
                _ = RefreshRemotePasswordStateAsync();
                ScheduleRemoteVaultStateRefresh();
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
            if (SetProperty(ref _fileSyncPath, value))
            {
                if (!_isLoadingSyncSettings)
                {
                    MarkSyncSettingsDirty();
                }

                EvaluateSyncConfigurationState(false);
                ScheduleRemoteVaultStateRefresh();
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
                EvaluateSyncConfigurationState(false);
                ScheduleRemoteVaultStateRefresh();
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

    public bool IsSyncConfigured
    {
        get => _isSyncConfigured;
        private set
        {
            if (SetProperty(ref _isSyncConfigured, value))
            {
                OnPropertyChanged(nameof(IsSyncSummaryVisible));
                OnPropertyChanged(nameof(IsSyncSetupVisible));
                OnPropertyChanged(nameof(IsCancelSyncEditVisible));
                UpdateSyncCommandStates();
            }
        }
    }

    public bool IsEditingSyncSettings
    {
        get => _isEditingSyncSettings;
        private set
        {
            if (SetProperty(ref _isEditingSyncSettings, value))
            {
                OnPropertyChanged(nameof(IsSyncSummaryVisible));
                OnPropertyChanged(nameof(IsSyncSetupVisible));
                OnPropertyChanged(nameof(IsCancelSyncEditVisible));
                UpdateSyncCommandStates();
            }
        }
    }

    public bool IsSyncSummaryVisible => IsSyncConfigured && !IsEditingSyncSettings;

    public bool IsSyncSetupVisible => !IsSyncConfigured || IsEditingSyncSettings;

    public bool IsCancelSyncEditVisible => IsSyncConfigured && IsEditingSyncSettings;

    public string SyncSummaryProviderName
    {
        get => _syncSummaryProviderName;
        private set => SetProperty(ref _syncSummaryProviderName, value);
    }

    public string SyncSummaryConnectionDetail
    {
        get => _syncSummaryConnectionDetail;
        private set => SetProperty(ref _syncSummaryConnectionDetail, value);
    }

    public string SyncSummaryLastSync
    {
        get => _syncSummaryLastSync;
        private set => SetProperty(ref _syncSummaryLastSync, value);
    }

    public string SyncSummaryNextSync
    {
        get => _syncSummaryNextSync;
        private set => SetProperty(ref _syncSummaryNextSync, value);
    }

    public string SyncSummaryRemoteInfo
    {
        get => _syncSummaryRemoteInfo;
        private set => SetProperty(ref _syncSummaryRemoteInfo, value);
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

        _remoteStateRefreshCts?.Cancel();
        _remoteStateRefreshCts?.Dispose();
        _remoteStateRefreshCts = null;
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
                EvaluateSyncConfigurationState(false);
            }).ConfigureAwait(false);
            MainThread.BeginInvokeOnMainThread(ScheduleRemoteVaultStateRefresh);
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
            var remotePasswordChanged = false;

            try
            {
                remotePasswordChanged = await ApplyRemotePasswordUpdatesAsync(providerKey).ConfigureAwait(false);
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
            var syncResult = await PostProcessRemotePasswordAsync(configuration, remotePasswordChanged).ConfigureAwait(false);
            await RefreshSyncStatusAsync(syncResult).ConfigureAwait(false);
            await MainThread.InvokeOnMainThreadAsync(() => EvaluateSyncConfigurationState(true)).ConfigureAwait(false);
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

        if (IsRemotePasswordConfirmationVisible && !string.Equals(password, confirm, StringComparison.Ordinal))
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
            RemotePasswordSuccess = null;
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

    private async Task<VaultSyncResult?> PostProcessRemotePasswordAsync(VaultSyncConfiguration configuration, bool remotePasswordChanged, CancellationToken cancellationToken = default)
    {
        if (!IsRemotePasswordProviderSelected)
        {
            UpdateRemoteVaultExistence(false);
            MainThread.BeginInvokeOnMainThread(() => EvaluateSyncConfigurationState(true));
            return null;
        }

        var remoteState = await _vaultService.TryGetRemoteStateAsync(configuration, cancellationToken).ConfigureAwait(false);
        await MainThread.InvokeOnMainThreadAsync(() => UpdateRemoteVaultExistence(remoteState is not null)).ConfigureAwait(false);

        var remoteExists = remoteState is not null;

        if (remotePasswordChanged && remoteExists)
        {
            return await ValidateRemotePasswordAndSyncAsync(configuration, cancellationToken).ConfigureAwait(false);
        }

        if (remotePasswordChanged && !remoteExists)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                RemotePasswordError = null;
                RemotePasswordSuccess = "Remote-Passwort gespeichert. Erster Abgleich wird gestartet.";
            }).ConfigureAwait(false);
        }

        if (!configuration.IsEnabled)
        {
            return null;
        }

        await MainThread.InvokeOnMainThreadAsync(() => IsSyncBusy = true).ConfigureAwait(false);
        try
        {
            var result = await _vaultService.SynchronizeAsync(preferDownload: remoteExists, cancellationToken: cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsSyncBusy = false).ConfigureAwait(false);
        }
    }

    private async Task<VaultSyncResult?> ValidateRemotePasswordAndSyncAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        RemoteVaultValidationResult validation;

        try
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsRemotePasswordBusy = true).ConfigureAwait(false);
            validation = await _vaultService.ValidateRemotePasswordAsync(configuration, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                RemotePasswordError = ex.Message;
                RemotePasswordSuccess = null;
            }).ConfigureAwait(false);
            return null;
        }
        finally
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsRemotePasswordBusy = false).ConfigureAwait(false);
        }

        await MainThread.InvokeOnMainThreadAsync(() => UpdateRemoteVaultExistence(validation.RemoteExists)).ConfigureAwait(false);

        if (!validation.RemoteExists)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                RemotePasswordError = null;
                RemotePasswordSuccess = "Remote-Passwort gespeichert. Die Cloud-Datei wird beim ersten Synchronisieren erstellt.";
            }).ConfigureAwait(false);
            return null;
        }

        if (!validation.Success)
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                RemotePasswordError = validation.ErrorMessage ?? "Das Remote-Passwort ist ungültig.";
                RemotePasswordSuccess = null;
            }).ConfigureAwait(false);
            return null;
        }

        await MainThread.InvokeOnMainThreadAsync(() =>
        {
            RemotePasswordError = null;
            RemotePasswordSuccess = validation.EntryCount.HasValue
                ? FormatRemoteValidationSuccess(validation.EntryCount.Value)
                : "Remote-Passwort bestätigt.";
        }).ConfigureAwait(false);

        await MainThread.InvokeOnMainThreadAsync(() => IsSyncBusy = true).ConfigureAwait(false);
        try
        {
            var result = await _vaultService.SynchronizeAsync(preferDownload: true, cancellationToken: cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally
        {
            await MainThread.InvokeOnMainThreadAsync(() => IsSyncBusy = false).ConfigureAwait(false);
        }
    }

    private static string FormatRemoteValidationSuccess(int entryCount)
        => entryCount == 1
            ? "Remote-Passwort bestätigt. 1 Eintrag gefunden."
            : $"Remote-Passwort bestätigt. {entryCount} Einträge gefunden.";

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
                EvaluateSyncConfigurationState(true);
            }).ConfigureAwait(false);
            return;
        }

        if (string.IsNullOrWhiteSpace(providerKey))
        {
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                IsRemotePasswordConfigured = false;
                RemotePasswordSuccess = null;
                EvaluateSyncConfigurationState(true);
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
            EvaluateSyncConfigurationState(true);
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

    private void ScheduleRemoteVaultStateRefresh()
    {
        _remoteStateRefreshCts?.Cancel();
        _remoteStateRefreshCts?.Dispose();
        _remoteStateRefreshCts = null;

        if (!IsRemotePasswordProviderSelected)
        {
            UpdateRemoteVaultExistence(false);
            return;
        }

        var configuration = BuildSyncConfiguration();
        if (string.IsNullOrWhiteSpace(configuration.ProviderKey))
        {
            UpdateRemoteVaultExistence(false);
            return;
        }

        var cts = new CancellationTokenSource();
        _remoteStateRefreshCts = cts;

        Task.Run(async () =>
        {
            try
            {
                await Task.Delay(300, cts.Token).ConfigureAwait(false);
                var remoteState = await _vaultService.TryGetRemoteStateAsync(configuration, cts.Token).ConfigureAwait(false);
                await MainThread.InvokeOnMainThreadAsync(() => UpdateRemoteVaultExistence(remoteState is not null)).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        });
    }

    private void UpdateRemoteVaultExistence(bool exists)
    {
        if (MainThread.IsMainThread)
        {
            HasExistingRemoteVault = exists;
        }
        else
        {
            MainThread.BeginInvokeOnMainThread(() => HasExistingRemoteVault = exists);
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

        if (result?.RemoteState is not null || status.RemoteState is not null)
        {
            UpdateRemoteVaultExistence(true);
        }

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
        else
        {
            var changeSummary = BuildSyncChangeSummary(status, result);
            if (!string.IsNullOrWhiteSpace(changeSummary))
            {
                builder.Append(" • ").Append(changeSummary);
            }

            var remote = result?.RemoteState ?? status.RemoteState;
            if (remote is not null)
            {
                builder.Append(" • Remote-Stand: ").Append(remote.LastModifiedUtc.ToLocalTime().ToString("g"));
            }
        }

        SyncStatusMessage = builder.ToString();
        UpdateSyncSummaryDetails(status);
    }

    private static string? BuildSyncChangeSummary(VaultSyncStatus status, VaultSyncResult? result)
    {
        var parts = new List<string>();

        var operation = result?.Operation ?? status.LastOperation;
        var downloadedEntries = result?.DownloadedEntries ?? status.LastDownloadedEntries;
        var uploadedEntries = result?.UploadedEntries ?? status.LastUploadedEntries;

        if (downloadedEntries is int downloaded)
        {
            parts.Add(downloaded == 1 ? "1 Eintrag geladen" : $"{downloaded} Einträge geladen");
        }
        else if (operation == VaultSyncOperation.Downloaded)
        {
            parts.Add("Einträge geladen: Anzahl unbekannt (Tresor gesperrt)");
        }

        if (uploadedEntries is int uploaded)
        {
            parts.Add(uploaded == 1 ? "1 Eintrag hochgeladen" : $"{uploaded} Einträge hochgeladen");
        }
        else if (operation == VaultSyncOperation.Uploaded)
        {
            parts.Add("Einträge hochgeladen: Anzahl unbekannt (Tresor gesperrt)");
        }

        if (parts.Count == 0)
        {
            if (operation == VaultSyncOperation.UpToDate)
            {
                parts.Add("Keine Änderungen");
            }
            else
            {
                return null;
            }
        }

        return string.Join(", ", parts);
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

    private void EnterSyncEditMode()
    {
        IsEditingSyncSettings = true;
    }

    private async Task CancelSyncEditingAsync()
    {
        await LoadSyncConfigurationAsync().ConfigureAwait(false);
        await MainThread.InvokeOnMainThreadAsync(() => EvaluateSyncConfigurationState(true)).ConfigureAwait(false);
    }

    private void EvaluateSyncConfigurationState(bool allowCollapse)
    {
        var configured = DetermineSyncConfigured();
        IsSyncConfigured = configured;

        if (!configured)
        {
            if (!IsEditingSyncSettings)
            {
                IsEditingSyncSettings = true;
            }

            return;
        }

        if (allowCollapse && !IsSyncSettingsDirty)
        {
            IsEditingSyncSettings = false;
        }
    }

    private bool DetermineSyncConfigured()
    {
        if (!IsSyncEnabled)
        {
            return false;
        }

        var providerKey = SelectedSyncProvider?.Key;
        if (string.IsNullOrWhiteSpace(providerKey))
        {
            return false;
        }

        if (IsFileProviderSelected && string.IsNullOrWhiteSpace(FileSyncPath))
        {
            return false;
        }

        if (IsGoogleDriveProviderSelected && string.IsNullOrWhiteSpace(GoogleDriveDocumentUri))
        {
            return false;
        }

        if (IsRemotePasswordProviderSelected && !IsRemotePasswordConfigured)
        {
            return false;
        }

        return true;
    }

    private string BuildConnectionDetail(string? providerKey, string providerName)
    {
        if (string.Equals(providerKey, FileSystemVaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase))
        {
            return string.IsNullOrWhiteSpace(FileSyncPath)
                ? $"{providerName}: Keine Datei ausgewählt."
                : $"{providerName}: {FileSyncPath}";
        }

        if (string.Equals(providerKey, GoogleDriveVaultSyncProvider.ProviderKey, StringComparison.OrdinalIgnoreCase))
        {
            return string.IsNullOrWhiteSpace(GoogleDriveDocumentUri)
                ? $"{providerName}: Keine Datei verknüpft."
                : $"{providerName}: {FormatGoogleDriveDocumentName(GoogleDriveDocumentUri)}";
        }

        return $"Verbindung: {providerName}";
    }

    private void UpdateSyncSummaryDetails(VaultSyncStatus status)
    {
        if (!status.IsEnabled || string.IsNullOrWhiteSpace(status.ProviderKey))
        {
            SyncSummaryProviderName = "Synchronisation deaktiviert";
            SyncSummaryConnectionDetail = "Aktiviere die Synchronisation, um automatische Updates zu erhalten.";
        }
        else
        {
            var providerName = _syncProviders.FirstOrDefault(p => string.Equals(p.Key, status.ProviderKey, StringComparison.OrdinalIgnoreCase))?.DisplayName
                ?? SelectedSyncProvider?.DisplayName
                ?? "Unbekannter Anbieter";
            SyncSummaryProviderName = providerName;
            SyncSummaryConnectionDetail = BuildConnectionDetail(status.ProviderKey, providerName);
        }

        SyncSummaryLastSync = status.LastSyncUtc is DateTimeOffset lastSync
            ? $"Letzte Synchronisation: {lastSync.ToLocalTime():g}"
            : "Noch keine Synchronisation durchgeführt.";

        if (!status.IsEnabled)
        {
            SyncSummaryNextSync = "Synchronisation deaktiviert.";
        }
        else if (!status.AutoSyncEnabled)
        {
            SyncSummaryNextSync = "Automatische Synchronisation deaktiviert.";
        }
        else if (status.NextAutoSyncUtc is DateTimeOffset nextSync)
        {
            SyncSummaryNextSync = $"Nächste automatische Synchronisation spätestens um {nextSync.ToLocalTime():g}.";
        }
        else
        {
            SyncSummaryNextSync = "Automatische Synchronisation aktiv.";
        }

        SyncSummaryRemoteInfo = status.RemoteState is { } remote
            ? $"Stand der Cloud-Datei: {remote.LastModifiedUtc.ToLocalTime():g}"
            : "Cloud-Datei wurde noch nicht erstellt.";
    }

    private static string FormatGoogleDriveDocumentName(string uri)
    {
        if (string.IsNullOrWhiteSpace(uri))
        {
            return "Datei verknüpft";
        }

        var trimmed = uri.TrimEnd('/');
        var separatorIndex = trimmed.LastIndexOf('/');
        if (separatorIndex >= 0 && separatorIndex < trimmed.Length - 1)
        {
            return trimmed[(separatorIndex + 1)..];
        }

        return trimmed;
    }

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
        MainThread.BeginInvokeOnMainThread(_editSyncSettingsCommand.ChangeCanExecute);
        MainThread.BeginInvokeOnMainThread(_cancelSyncSettingsCommand.ChangeCanExecute);
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
