using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Vault;

namespace Password_Phrase_Producer.ViewModels;

public class DataVaultPageViewModel : INotifyPropertyChanged
{
    private const string AllCategoriesFilter = "Alle Kategorien";

    private readonly DataVaultService _vaultService;
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

    public DataVaultPageViewModel(DataVaultService vaultService, IBiometricAuthenticationService biometricAuthenticationService)
    {
        _vaultService = vaultService;
        _biometricAuthenticationService = biometricAuthenticationService;
        _entryGroups = new ObservableCollection<VaultEntryGroup>();
        CategoryFilterOptions = new ObservableCollection<string> { AllCategoriesFilter };

        UnlockCommand = new Command(async () => await UnlockAsync(), () => !IsBusy);
        UnlockWithBiometricCommand = new Command(async () => await UnlockWithBiometricAsync(), () => !IsBusy && CanUseBiometric && IsBiometricConfigured);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private ObservableCollection<VaultEntryGroup> _entryGroups;
    public ObservableCollection<VaultEntryGroup> EntryGroups
    {
        get => _entryGroups;
        private set
        {
            if (_entryGroups != value)
            {
                _entryGroups = value;
                OnPropertyChanged();
            }
        }
    }

    public ObservableCollection<string> CategoryFilterOptions { get; }

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

        MessagingCenter.Subscribe<DataVaultService>(this, DataVaultMessages.EntriesChanged, OnVaultEntriesChanged);
        _isListening = true;
    }

    public void Deactivate()
    {
        if (_isListening)
        {
            MessagingCenter.Unsubscribe<DataVaultService>(this, DataVaultMessages.EntriesChanged);
            _isListening = false;
        }

        _vaultService.Lock();
        IsUnlocked = false;
        _hasAttemptedAutoBiometric = false;
        _allEntries.Clear();
        _availableCategories.Clear();
        MainThread.BeginInvokeOnMainThread(() =>
        {
            EntryGroups = new ObservableCollection<VaultEntryGroup>();
            CategoryFilterOptions.Clear();
            CategoryFilterOptions.Add(AllCategoriesFilter);
            _selectedCategory = AllCategoriesFilter;
            OnPropertyChanged(nameof(SelectedCategory));
        });
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await EnsureAccessStateAsync(cancellationToken);

        if (IsUnlocked)
        {
            await ReloadAsync(cancellationToken);
        }
    }

    public async Task ReloadAsync(CancellationToken cancellationToken = default, bool allowWhileBusy = false)
    {
        if ((!allowWhileBusy && IsBusy) || !IsUnlocked)
        {
            return;
        }

        try
        {
            IsBusy = true;
            var entries = await _vaultService.GetEntriesAsync(cancellationToken);
            UpdateEntries(entries);
        }
        catch (InvalidDataException ex)
        {
            UnlockError = $"Fehler: {ex.Message}";
            IsUnlocked = false;
        }
        catch (Exception ex)
        {
            UnlockError = "Ein unerwarteter Fehler ist aufgetreten.";
            Debug.WriteLine(ex);
        }
        finally
        {
            IsBusy = false;
        }
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

    public Task<byte[]> ExportDataVaultWithFilePasswordAsync(string filePassword, CancellationToken cancellationToken = default)
        => _vaultService.ExportWithFilePasswordAsync(filePassword, cancellationToken);

    public Task ImportDataVaultWithFilePasswordAsync(Stream stream, string filePassword, CancellationToken cancellationToken = default)
        => _vaultService.ImportWithFilePasswordAsync(stream, filePassword, cancellationToken);

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
                EntryGroups = new ObservableCollection<VaultEntryGroup>();
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

                if (CanUseBiometric && EnableBiometric != IsBiometricConfigured)
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
        catch (UnauthorizedAccessException)
        {
            UnlockError = "Die biometrische Authentifizierung wurde abgebrochen.";
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
        await ReloadAsync(cancellationToken, allowWhileBusy: true);
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

    private async void OnVaultEntriesChanged(DataVaultService sender)
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
            Debug.WriteLine($"Fehler beim Aktualisieren des Datentresors: {ex}");
        }
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
            .Select(group => new VaultEntryGroup(group.Key, group.OrderBy(entry => entry.Label, StringComparer.CurrentCultureIgnoreCase).ToList()))
            .ToList();

        // Replace entire collection instead of Clear/Add to avoid MAUI CollectionView grouping bug
        EntryGroups = new ObservableCollection<VaultEntryGroup>(grouped);
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
