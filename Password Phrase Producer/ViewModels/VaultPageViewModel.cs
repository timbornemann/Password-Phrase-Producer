using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Vault;
using Password_Phrase_Producer.Services.Vault.Sync;
using System.Linq;
using System.Text;

namespace Password_Phrase_Producer.ViewModels;

public class VaultPageViewModel : INotifyPropertyChanged
{
    private readonly PasswordVaultService _vaultService;
    private readonly IBiometricAuthenticationService _biometricAuthenticationService;
    private bool _isBusy;
    private bool _isListening;
    private bool _isUnlocked;
    private bool _isNewVault;
    private bool _canUseBiometric;
    private bool _isBiometricConfigured;
    private bool _enableBiometric;
    private string _password = string.Empty;
    private string _confirmPassword = string.Empty;
    private string? _unlockError;
    private bool _hasAttemptedAutoBiometric;
    private string _searchQuery = string.Empty;
    private string _selectedCategory = AllCategoriesFilter;
    private readonly List<PasswordVaultEntry> _allEntries = new();
    private readonly List<string> _availableCategories = new();
    private readonly ObservableCollection<VaultSyncProviderDescriptor> _syncProviders = new();
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
    private readonly IGoogleDriveDocumentPicker _googleDriveDocumentPicker;
    private readonly Command _selectGoogleDriveDocumentCommand;
    private readonly Command _clearGoogleDriveDocumentCommand;
    private string _googleDriveDocumentUri = string.Empty;
    private string? _currentS3Secret;
    private bool _hasS3Secret;
    private DateTimeOffset? _lastSyncUtc;
    private VaultSyncOperation _lastSyncOperation = VaultSyncOperation.None;
    private string? _lastSyncError;

    private const string AllCategoriesFilter = "Alle Kategorien";

    public VaultPageViewModel(PasswordVaultService vaultService, IBiometricAuthenticationService biometricAuthenticationService, IGoogleDriveDocumentPicker googleDriveDocumentPicker)
    {
        _vaultService = vaultService;
        _biometricAuthenticationService = biometricAuthenticationService;
        _googleDriveDocumentPicker = googleDriveDocumentPicker;
        EntryGroups = new ObservableCollection<VaultEntryGroup>();
        CategoryFilterOptions = new ObservableCollection<string> { AllCategoriesFilter };
        SyncProviders = _syncProviders;

        UnlockCommand = new Command(async () => await UnlockAsync(), () => !IsBusy);
        UnlockWithBiometricCommand = new Command(async () => await UnlockWithBiometricAsync(), () => !IsBusy && CanUseBiometric && IsBiometricConfigured);
        SaveSyncSettingsCommand = new Command(async () => await SaveSyncSettingsAsync(), () => IsSyncSettingsDirty && !IsSyncBusy);
        SyncNowCommand = new Command(async () => await SyncNowAsync(), () => !IsSyncBusy && IsSyncEnabled);
        _selectGoogleDriveDocumentCommand = new Command(async () => await SelectGoogleDriveDocumentAsync(), () => !IsSyncBusy && IsGoogleDriveProviderSelected);
        _clearGoogleDriveDocumentCommand = new Command(ClearGoogleDriveDocumentSelection, () => !IsSyncBusy && IsGoogleDriveProviderSelected && !string.IsNullOrWhiteSpace(GoogleDriveDocumentUri));
        SelectGoogleDriveDocumentCommand = _selectGoogleDriveDocumentCommand;
        ClearGoogleDriveDocumentCommand = _clearGoogleDriveDocumentCommand;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<VaultEntryGroup> EntryGroups { get; }

    public ObservableCollection<string> CategoryFilterOptions { get; }

    public ObservableCollection<VaultSyncProviderDescriptor> SyncProviders { get; }

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

    public ICommand SelectGoogleDriveDocumentCommand { get; }

    public ICommand ClearGoogleDriveDocumentCommand { get; }

    public bool HasS3Secret
    {
        get => _hasS3Secret;
        private set => SetProperty(ref _hasS3Secret, value);
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

    public ICommand SaveSyncSettingsCommand { get; }

    public ICommand SyncNowCommand { get; }

    public IReadOnlyList<string> AvailableCategories => _availableCategories;

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            if (SetProperty(ref _searchQuery, value))
            {
                ApplyFilters();
            }
        }
    }

    public string SelectedCategory
    {
        get => _selectedCategory;
        set
        {
            if (SetProperty(ref _selectedCategory, value))
            {
                ApplyFilters();
            }
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                UpdateCommandStates();
            }
        }
    }

    public bool IsUnlocked
    {
        get => _isUnlocked;
        private set
        {
            if (SetProperty(ref _isUnlocked, value))
            {
                OnPropertyChanged(nameof(IsLocked));
            }
        }
    }

    public bool IsLocked => !IsUnlocked;

    public bool IsNewVault
    {
        get => _isNewVault;
        private set => SetProperty(ref _isNewVault, value);
    }

    public bool CanUseBiometric
    {
        get => _canUseBiometric;
        private set
        {
            if (SetProperty(ref _canUseBiometric, value))
            {
                UpdateCommandStates();
            }
        }
    }

    public bool IsBiometricConfigured
    {
        get => _isBiometricConfigured;
        private set
        {
            if (SetProperty(ref _isBiometricConfigured, value))
            {
                if (!value && EnableBiometric)
                {
                    EnableBiometric = false;
                }

                UpdateCommandStates();
            }
        }
    }

    public bool EnableBiometric
    {
        get => _enableBiometric;
        set => SetProperty(ref _enableBiometric, value);
    }

    public string Password
    {
        get => _password;
        set
        {
            if (SetProperty(ref _password, value) && !string.IsNullOrEmpty(_unlockError))
            {
                UnlockError = null;
            }
        }
    }

    public string ConfirmPassword
    {
        get => _confirmPassword;
        set
        {
            if (SetProperty(ref _confirmPassword, value) && !string.IsNullOrEmpty(_unlockError))
            {
                UnlockError = null;
            }
        }
    }

    public string? UnlockError
    {
        get => _unlockError;
        private set => SetProperty(ref _unlockError, value);
    }

    public ICommand UnlockCommand { get; }

    public ICommand UnlockWithBiometricCommand { get; }

    public void Activate()
    {
        if (_isListening)
        {
            return;
        }

        MessagingCenter.Subscribe<PasswordVaultService>(this, VaultMessages.EntriesChanged, OnVaultEntriesChanged);
        MessagingCenter.Subscribe<PasswordVaultService, VaultSyncResult>(this, VaultMessages.SyncStatusChanged, OnSyncStatusChanged);
        _isListening = true;
    }

    public void Deactivate()
    {
        if (_isListening)
        {
            MessagingCenter.Unsubscribe<PasswordVaultService>(this, VaultMessages.EntriesChanged);
            MessagingCenter.Unsubscribe<PasswordVaultService, VaultSyncResult>(this, VaultMessages.SyncStatusChanged);
            _isListening = false;
        }

        _vaultService.Lock();
        IsUnlocked = false;
        _hasAttemptedAutoBiometric = false;
        _allEntries.Clear();
        _availableCategories.Clear();
        MainThread.BeginInvokeOnMainThread(() =>
        {
            EntryGroups.Clear();
            CategoryFilterOptions.Clear();
            CategoryFilterOptions.Add(AllCategoriesFilter);
            _selectedCategory = AllCategoriesFilter;
            OnPropertyChanged(nameof(SelectedCategory));
        });
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await LoadSyncConfigurationAsync(cancellationToken).ConfigureAwait(false);
        await EnsureAccessStateAsync(cancellationToken);

        if (IsUnlocked)
        {
            await ReloadAsync(cancellationToken);
        }
    }

    public async Task ReloadAsync(CancellationToken cancellationToken = default)
    {
        if (IsBusy || !IsUnlocked)
        {
            return;
        }

        try
        {
            IsBusy = true;
            var entries = await _vaultService.GetEntriesAsync(cancellationToken);
            UpdateEntries(entries);
        }
        finally
        {
            IsBusy = false;
        }
    }

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

    private async Task RefreshSyncStatusAsync(VaultSyncResult? result = null, CancellationToken cancellationToken = default)
    {
        var status = await _vaultService.GetSyncStatusAsync(cancellationToken).ConfigureAwait(false);
        await MainThread.InvokeOnMainThreadAsync(() => UpdateSyncStatusMessage(status, result)).ConfigureAwait(false);
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
            // Ignorieren – einige Provider unterstützen keine persistente Berechtigung.
        }

        GoogleDriveDocumentUri = string.Empty;
    }

    public async Task SaveEntryAsync(PasswordVaultEntry entry, CancellationToken cancellationToken = default)
    {
        await _vaultService.AddOrUpdateEntryAsync(entry, cancellationToken);
    }

    public async Task DeleteEntryAsync(PasswordVaultEntry entry, CancellationToken cancellationToken = default)
    {
        if (entry is null)
        {
            return;
        }

        await _vaultService.DeleteEntryAsync(entry.Id, cancellationToken);
    }

    public async Task ChangeMasterPasswordAsync(string newPassword, bool enableBiometric, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newPassword);

        await _vaultService.ChangeMasterPasswordAsync(newPassword, enableBiometric && CanUseBiometric, cancellationToken);

        EnableBiometric = enableBiometric && CanUseBiometric;
        IsBiometricConfigured = EnableBiometric;
    }

    public Task<byte[]> CreateBackupAsync(CancellationToken cancellationToken = default)
        => _vaultService.CreateBackupAsync(cancellationToken);

    public Task RestoreBackupAsync(Stream backupStream, CancellationToken cancellationToken = default)
        => _vaultService.RestoreBackupAsync(backupStream, cancellationToken);

    public Task<byte[]> ExportEncryptedVaultAsync(CancellationToken cancellationToken = default)
        => _vaultService.ExportEncryptedVaultAsync(cancellationToken);

    public Task ImportEncryptedVaultAsync(Stream encryptedStream, CancellationToken cancellationToken = default)
        => _vaultService.ImportEncryptedVaultAsync(encryptedStream, cancellationToken);

    public async Task EnsureAccessStateAsync(CancellationToken cancellationToken = default)
    {
        IsUnlocked = _vaultService.IsUnlocked;
        IsNewVault = !await _vaultService.HasMasterPasswordAsync(cancellationToken);
        CanUseBiometric = await _biometricAuthenticationService.IsAvailableAsync(cancellationToken);
        IsBiometricConfigured = CanUseBiometric && await _vaultService.HasBiometricKeyAsync(cancellationToken);
        EnableBiometric = IsBiometricConfigured;
        UnlockError = null;

        if (!IsUnlocked)
        {
            _allEntries.Clear();
            _availableCategories.Clear();
            MainThread.BeginInvokeOnMainThread(() =>
            {
                EntryGroups.Clear();
                CategoryFilterOptions.Clear();
                CategoryFilterOptions.Add(AllCategoriesFilter);
                _selectedCategory = AllCategoriesFilter;
                OnPropertyChanged(nameof(SelectedCategory));
            });

            if (CanUseBiometric && IsBiometricConfigured && !_hasAttemptedAutoBiometric)
            {
                _hasAttemptedAutoBiometric = true;
                await UnlockWithBiometricAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task UnlockAsync(CancellationToken cancellationToken = default)
    {
        if (IsBusy)
        {
            return;
        }

        try
        {
            IsBusy = true;
            UnlockError = null;

            if (string.IsNullOrWhiteSpace(Password))
            {
                UnlockError = "Bitte gib ein Passwort ein.";
                return;
            }

            if (IsNewVault)
            {
                if (!string.Equals(Password, ConfirmPassword, StringComparison.Ordinal))
                {
                    UnlockError = "Die Passwörter stimmen nicht überein.";
                    return;
                }

                await _vaultService.SetMasterPasswordAsync(Password, EnableBiometric && CanUseBiometric, cancellationToken);
                IsBiometricConfigured = EnableBiometric && CanUseBiometric;
                await OnUnlockedAsync(cancellationToken);
            }
            else
            {
                var unlocked = await _vaultService.UnlockAsync(Password, cancellationToken);
                if (!unlocked)
                {
                    UnlockError = "Das eingegebene Passwort ist ungültig.";
                    return;
                }

                if (CanUseBiometric)
                {
                    await _vaultService.SetBiometricUnlockAsync(EnableBiometric, cancellationToken);
                    IsBiometricConfigured = EnableBiometric;
                }

                await OnUnlockedAsync(cancellationToken);
            }
        }
        finally
        {
            IsBusy = false;
            UpdateCommandStates();
        }
    }

    private async Task UnlockWithBiometricAsync(CancellationToken cancellationToken = default)
    {
        if (IsBusy || !CanUseBiometric || !IsBiometricConfigured)
        {
            return;
        }

        try
        {
            IsBusy = true;
            UnlockError = null;

            var authenticated = await _biometricAuthenticationService.AuthenticateAsync("Authentifiziere dich, um den Tresor zu entsperren.", cancellationToken);
            if (!authenticated)
            {
                UnlockError = "Die biometrische Authentifizierung wurde abgebrochen.";
                return;
            }

            var unlocked = await _vaultService.TryUnlockWithStoredKeyAsync(cancellationToken);
            if (!unlocked)
            {
                UnlockError = "Der gespeicherte biometrische Schlüssel ist nicht mehr gültig. Bitte gib dein Passwort ein.";
                IsBiometricConfigured = false;
                return;
            }

            EnableBiometric = true;
            IsBiometricConfigured = true;
            await OnUnlockedAsync(cancellationToken);
        }
        finally
        {
            IsBusy = false;
            UpdateCommandStates();
        }
    }

    private async Task OnUnlockedAsync(CancellationToken cancellationToken)
    {
        Password = string.Empty;
        ConfirmPassword = string.Empty;
        UnlockError = null;
        IsUnlocked = true;
        IsNewVault = false;
        _hasAttemptedAutoBiometric = false;
        await ReloadAsync(cancellationToken);
    }

    private void UpdateEntries(IEnumerable<PasswordVaultEntry> entries)
    {
        var ordered = entries
            .OrderBy(e => e.DisplayCategory, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(e => e.Label, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        foreach (var entry in ordered)
        {
            entry.IsPasswordVisible = false;
        }

        _allEntries.Clear();
        _allEntries.AddRange(ordered);

        MainThread.BeginInvokeOnMainThread(() =>
        {
            UpdateCategoryFiltersOnMainThread();
            ApplyFiltersOnMainThread();
        });
    }

    private async void OnVaultEntriesChanged(PasswordVaultService sender)
    {
        try
        {
            await EnsureAccessStateAsync();
            if (IsUnlocked)
            {
                await ReloadAsync();
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Fehler beim Aktualisieren des Tresors: {ex}");
        }
    }

    private void OnSyncStatusChanged(PasswordVaultService sender, VaultSyncResult result)
    {
        _ = RefreshSyncStatusAsync(result).ContinueWith(task =>
        {
            if (task.Exception is not null)
            {
                Debug.WriteLine($"Fehler beim Aktualisieren des Sync-Status: {task.Exception}");
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

    private void UpdateCommandStates()
    {
        if (UnlockCommand is Command unlockCommand)
        {
            MainThread.BeginInvokeOnMainThread(unlockCommand.ChangeCanExecute);
        }

        if (UnlockWithBiometricCommand is Command biometricCommand)
        {
            MainThread.BeginInvokeOnMainThread(biometricCommand.ChangeCanExecute);
        }

        UpdateSyncCommandStates();
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

    private void ApplyFilters()
        => MainThread.BeginInvokeOnMainThread(ApplyFiltersOnMainThread);

    private void ApplyFiltersOnMainThread()
    {
        var query = SearchQuery?.Trim();
        var selectedCategory = SelectedCategory;

        IEnumerable<PasswordVaultEntry> filtered = _allEntries;

        if (!string.IsNullOrWhiteSpace(query))
        {
            filtered = filtered.Where(entry =>
                entry.Label.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
                entry.Username.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
                entry.Url.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
                entry.Notes.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
                entry.FreeText.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
                entry.DisplayCategory.Contains(query, StringComparison.CurrentCultureIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(selectedCategory) &&
            !string.Equals(selectedCategory, AllCategoriesFilter, StringComparison.CurrentCultureIgnoreCase))
        {
            filtered = filtered.Where(entry => string.Equals(entry.DisplayCategory, selectedCategory, StringComparison.CurrentCultureIgnoreCase));
        }

        var grouped = filtered
            .GroupBy(entry => entry.DisplayCategory, StringComparer.CurrentCultureIgnoreCase)
            .OrderBy(group => group.Key, StringComparer.CurrentCultureIgnoreCase)
            .Select(group => new VaultEntryGroup(group.Key, group.OrderBy(entry => entry.Label, StringComparer.CurrentCultureIgnoreCase)));

        EntryGroups.Clear();
        foreach (var group in grouped)
        {
            EntryGroups.Add(group);
        }
    }

    private void UpdateCategoryFiltersOnMainThread()
    {
        var categories = _allEntries
            .Select(entry => entry.DisplayCategory)
            .Distinct(StringComparer.CurrentCultureIgnoreCase)
            .OrderBy(category => category, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        _availableCategories.Clear();
        _availableCategories.AddRange(categories);

        CategoryFilterOptions.Clear();
        CategoryFilterOptions.Add(AllCategoriesFilter);

        foreach (var category in categories)
        {
            CategoryFilterOptions.Add(category);
        }

        var hasSelectedCategory = categories.Any(category => string.Equals(category, SelectedCategory, StringComparison.CurrentCultureIgnoreCase));
        if (string.IsNullOrWhiteSpace(SelectedCategory) ||
            (!string.Equals(SelectedCategory, AllCategoriesFilter, StringComparison.CurrentCultureIgnoreCase) && !hasSelectedCategory))
        {
            _selectedCategory = AllCategoriesFilter;
            OnPropertyChanged(nameof(SelectedCategory));
        }
    }

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
