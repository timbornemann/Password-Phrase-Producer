using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services;

namespace Password_Phrase_Producer.ViewModels;

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
