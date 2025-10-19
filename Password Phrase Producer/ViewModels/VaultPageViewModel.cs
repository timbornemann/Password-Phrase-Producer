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
using System.Linq;

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

    public VaultPageViewModel(PasswordVaultService vaultService, IBiometricAuthenticationService biometricAuthenticationService)
    {
        _vaultService = vaultService;
        _biometricAuthenticationService = biometricAuthenticationService;
        Entries = new ObservableCollection<PasswordVaultEntry>();

        UnlockCommand = new Command(async () => await UnlockAsync(), () => !IsBusy);
        UnlockWithBiometricCommand = new Command(async () => await UnlockWithBiometricAsync(), () => !IsBusy && CanUseBiometric && IsBiometricConfigured);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<PasswordVaultEntry> Entries { get; }

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
        _isListening = true;
    }

    public void Deactivate()
    {
        if (_isListening)
        {
            MessagingCenter.Unsubscribe<PasswordVaultService>(this, VaultMessages.EntriesChanged);
            _isListening = false;
        }

        _vaultService.Lock();
        IsUnlocked = false;
        MainThread.BeginInvokeOnMainThread(() => Entries.Clear());
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
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
            MainThread.BeginInvokeOnMainThread(Entries.Clear);
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
        await ReloadAsync(cancellationToken);
    }

    private void UpdateEntries(IEnumerable<PasswordVaultEntry> entries)
    {
        var ordered = entries
            .OrderBy(e => e.DisplayCategory, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(e => e.Label, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

        MainThread.BeginInvokeOnMainThread(() =>
        {
            Entries.Clear();
            foreach (var entry in ordered)
            {
                Entries.Add(entry);
            }
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
