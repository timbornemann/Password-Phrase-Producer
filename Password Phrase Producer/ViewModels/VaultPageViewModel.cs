using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Vault;

namespace Password_Phrase_Producer.ViewModels;

public class VaultPageViewModel : INotifyPropertyChanged
{
    private readonly PasswordVaultService _vaultService;
    private bool _isBusy;
    private bool _isListening;

    public VaultPageViewModel(PasswordVaultService vaultService)
    {
        _vaultService = vaultService;
        Entries = new ObservableCollection<PasswordVaultEntry>();
    }

    public ObservableCollection<PasswordVaultEntry> Entries { get; }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (_isBusy != value)
            {
                _isBusy = value;
                OnPropertyChanged();
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

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
        if (!_isListening)
        {
            return;
        }

        MessagingCenter.Unsubscribe<PasswordVaultService>(this, VaultMessages.EntriesChanged);
        _isListening = false;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (Entries.Count > 0)
        {
            return;
        }

        await ReloadAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ReloadAsync(CancellationToken cancellationToken = default)
    {
        if (IsBusy)
        {
            return;
        }

        try
        {
            IsBusy = true;
            var entries = await _vaultService.GetEntriesAsync(cancellationToken).ConfigureAwait(false);
            UpdateEntries(entries);
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task SaveEntryAsync(PasswordVaultEntry entry, CancellationToken cancellationToken = default)
    {
        await _vaultService.AddOrUpdateEntryAsync(entry, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteEntryAsync(PasswordVaultEntry entry, CancellationToken cancellationToken = default)
    {
        if (entry is null)
        {
            return;
        }

        await _vaultService.DeleteEntryAsync(entry.Id, cancellationToken).ConfigureAwait(false);
    }

    public Task<byte[]> CreateBackupAsync(CancellationToken cancellationToken = default)
        => _vaultService.CreateBackupAsync(cancellationToken);

    public Task RestoreBackupAsync(Stream backupStream, CancellationToken cancellationToken = default)
        => _vaultService.RestoreBackupAsync(backupStream, cancellationToken);

    public Task<byte[]> ExportEncryptedVaultAsync(CancellationToken cancellationToken = default)
        => _vaultService.ExportEncryptedVaultAsync(cancellationToken);

    public Task ImportEncryptedVaultAsync(Stream encryptedStream, CancellationToken cancellationToken = default)
        => _vaultService.ImportEncryptedVaultAsync(encryptedStream, cancellationToken);

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
            await ReloadAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Fehler beim Aktualisieren des Tresors: {ex}");
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
