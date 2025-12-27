using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Windows.Input;
using Microsoft.Maui.ApplicationModel;
using CommunityToolkit.Maui.Views;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Views;
using Password_Phrase_Producer.Views.Dialogs;

namespace Password_Phrase_Producer.ViewModels;

public class AuthenticatorViewModel : INotifyPropertyChanged
{
    private readonly TotpService _totpService;
    private readonly IDispatcher _dispatcher;
    private IDispatcherTimer? _timer;
    private bool _isBusy;
    private bool _isActive;

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<TotpViewModelItem> Entries { get; } = new();

    public ICommand AddEntryCommand { get; }
    public ICommand DeleteEntryCommand { get; }
    public ICommand CopyCodeCommand { get; }
    public ICommand RefreshCommand { get; }

    public bool IsBusy
    {
        get => _isBusy;
        set => SetProperty(ref _isBusy, value);
    }

    public AuthenticatorViewModel(TotpService totpService)
    {
        _totpService = totpService;
        _dispatcher = Application.Current?.Dispatcher ?? Dispatcher.GetForCurrentThread()!;

        AddEntryCommand = new Command(AddEntryAsync);
        DeleteEntryCommand = new Command<TotpViewModelItem>(DeleteEntryAsync);
        CopyCodeCommand = new Command<TotpViewModelItem>(CopyCodeAsync);
        RefreshCommand = new Command(async () => await LoadEntriesAsync());

        _totpService.EntriesChanged += OnEntriesChanged;
    }

    public void Activate()
    {
        if (_isActive) return;
        _isActive = true;
        
        StartTimer();
        Task.Run(() => LoadEntriesAsync());
    }

    public void Deactivate()
    {
        _isActive = false;
        StopTimer();
    }

    private void StartTimer()
    {
        if (_timer == null)
        {
            _timer = _dispatcher.CreateTimer();
            _timer.Interval = TimeSpan.FromSeconds(1);
            _timer.Tick += (s, e) => _dispatcher.Dispatch(UpdateCodes);
        }
        _timer.Start();
        _dispatcher.Dispatch(UpdateCodes); // Initial update
    }

    private void StopTimer()
    {
        _timer?.Stop();
    }

    private void UpdateCodes()
    {
        foreach (var item in Entries)
        {
            var result = _totpService.GenerateCode(item.Entry);
            if (result != null)
            {
                item.Code = FormatCode(result.Code);
                item.RemainingSeconds = result.RemainingSeconds;
                item.Period = result.Period;
                item.Progress = (double)result.RemainingSeconds / result.Period;
            }
        }
    }

    private string FormatCode(string code)
    {
        if (code.Length == 6)
            return $"{code.Substring(0, 3)} {code.Substring(3)}";
        return code;
    }

    private async Task LoadEntriesAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        try
        {
            var entries = await _totpService.GetEntriesAsync();
            var viewModels = entries.Select(e => new TotpViewModelItem(e)).ToList();

            _dispatcher.Dispatch(() =>
            {
                Entries.Clear();
                foreach (var vm in viewModels)
                {
                    Entries.Add(vm);
                }
                UpdateCodes();
            });
        }
        catch (InvalidDataException ex)
        {
            // Show error to user
             _dispatcher.Dispatch(async () => 
             {
                 if (Application.Current?.MainPage is Page page)
                 {
                     await page.DisplayAlert("Fehler", $"Die Authenticator-Daten konnten nicht geladen werden: {ex.Message}", "OK");
                 }
             });
        }
        catch (Exception ex)
        {
             _dispatcher.Dispatch(async () => 
             {
                 if (Application.Current?.MainPage is Page page)
                 {
                     await page.DisplayAlert("Fehler", "Ein unerwarteter Fehler ist beim Laden der Authenticator-Daten aufgetreten.", "OK");
                 }
             });

        }
        finally
        {
            IsBusy = false;
        }
    }

    private async void OnEntriesChanged(object? sender, EventArgs e)
    {
        await LoadEntriesAsync();
    }

    private async void AddEntryAsync()
    {
        // Use custom AddEntryPage modal
        var page = Application.Current?.MainPage?.Handler?.MauiContext?.Services.GetService<AddEntryPage>();
        if (page is null)
        {
            return;
        }

        var currentPage = GetCurrentPage();
        var navigation = currentPage?.Navigation;
        if (navigation is null)
        {
            return;
        }

        await navigation.PushModalAsync(page);
    }

    private async void DeleteEntryAsync(TotpViewModelItem? item)
    {
        if (item == null) return;

        var page = GetCurrentPage();
        if (page is null)
        {
            return;
        }

        var popup = new ConfirmationPopup(
            "Eintrag löschen",
            $"Möchtest du '{item.Issuer} ({item.AccountName})' wirklich löschen?",
            "Löschen",
            "Abbrechen",
            confirmIsDestructive: true);

        var result = await page.ShowPopupAsync(popup);
        if (result is bool confirm && confirm)
        {
            await _totpService.DeleteEntryAsync(item.Entry.Id);
        }
    }

    private async void CopyCodeAsync(TotpViewModelItem? item)
    {
        if (item == null) return;
        
        // Remove spaces for clipboard
        var cleanCode = item.Code.Replace(" ", "");
        await Clipboard.SetTextAsync(cleanCode);

        // Visual feedback for copy button + toast (match Vault behavior)
        var token = item.NextCopyFeedbackToken();
        item.IsCopyFeedbackActive = true;
        await ToastService.ShowCopiedAsync("Code");

        _ = Task.Run(async () =>
        {
            await Task.Delay(700);
            MainThread.BeginInvokeOnMainThread(() =>
            {
                if (item.CopyFeedbackToken == token)
                {
                    item.IsCopyFeedbackActive = false;
                }
            });
        });
    }

    private static Page? GetCurrentPage()
    {
        try
        {
            if (Application.Current?.MainPage is Page mainPage)
            {
                if (mainPage is Shell shell)
                {
                    return shell.CurrentPage;
                }

                if (mainPage is NavigationPage navPage)
                {
                    return navPage.CurrentPage;
                }

                return mainPage;
            }
        }
        catch
        {
        }

        return null;
    }

    private bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }
}

public class TotpViewModelItem : INotifyPropertyChanged
{
    private string _code = "--- ---";
    private int _remainingSeconds;
    private double _progress;
    private int _period = 30;
    private bool _isCopyFeedbackActive;
    private int _copyFeedbackToken;

    public TotpEntry Entry { get; }

    public event PropertyChangedEventHandler? PropertyChanged;

    public TotpViewModelItem(TotpEntry entry)
    {
        Entry = entry;
    }

    public string Issuer => Entry.Issuer;
    public string AccountName => Entry.AccountName;

    public string Code
    {
        get => _code;
        set { if (_code != value) { _code = value; OnPropertyChanged(); } }
    }

    public bool IsCopyFeedbackActive
    {
        get => _isCopyFeedbackActive;
        set { if (_isCopyFeedbackActive != value) { _isCopyFeedbackActive = value; OnPropertyChanged(); } }
    }

    public int CopyFeedbackToken => _copyFeedbackToken;

    public int NextCopyFeedbackToken()
        => Interlocked.Increment(ref _copyFeedbackToken);

    public int RemainingSeconds
    {
        get => _remainingSeconds;
        set { if (_remainingSeconds != value) { _remainingSeconds = value; OnPropertyChanged(); } }
    }

    public double Progress
    {
        get => _progress;
        set { if (Math.Abs(_progress - value) > 0.001) { _progress = value; OnPropertyChanged(); } }
    }

    public int Period
    {
        get => _period;
        set => _period = value;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        if (MainThread.IsMainThread)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
        else
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            });
        }
    }
}
