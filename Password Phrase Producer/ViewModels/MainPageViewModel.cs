using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques;
using Password_Phrase_Producer.PasswordGenerationTechniques.HashBasedTechniques;
using Password_Phrase_Producer.Windows.PasswordGenerationWindows;
using PasswordPhraseProducer.PasswordGenerationTechniques.TbvTechniques;

namespace Password_Phrase_Producer.ViewModels;

public class MainPageViewModel : INotifyPropertyChanged
{
    private PasswordModeOption? selectedMode;
    private View? currentContent;
    private bool isMenuVisible = true;

    public ObservableCollection<PasswordModeOption> ModeOptions { get; }

    public ICommand ShowMenuCommand { get; }
    public ICommand SelectModeCommand { get; }

    public event PropertyChangedEventHandler? PropertyChanged;

    public MainPageViewModel()
    {
        ModeOptions = new ObservableCollection<PasswordModeOption>
        {
            new(
                "1 Word Password",
                "Deterministic hash-based password generation",
                () => new HachBasedTechniquesUiPage(new DeterministicHashPasswordGenerator()),
                "🔐"),
            new(
                "Alternate Words",
                "Combine alternating phrases into a passphrase",
                () => new ConcatenationTechniquesUiPage(new AlternatingUpDownChaining()),
                "🧩"),
            new(
                "TBV1 With Errors",
                "Three block verification with error handling",
                () => new TbvUiPage(new TBV1WithErrors()),
                "🛡️"),
            new(
                "TBV1",
                "Classic three block verification",
                () => new TbvUiPage(new TBV1()),
                "🧱"),
            new(
                "TBV2",
                "Enhanced verification variant",
                () => new TbvUiPage(new TBV2()),
                "⚙️"),
            new(
                "TBV3",
                "Advanced verification with extra checks",
                () => new TbvUiPage(new TBV3()),
                "🚀")
        };

        ShowMenuCommand = new Command(ShowMenu);
        SelectModeCommand = new Command<PasswordModeOption>(SelectMode);
    }

    public PasswordModeOption? SelectedMode
    {
        get => selectedMode;
        set
        {
            if (selectedMode == value)
            {
                return;
            }

            selectedMode = value;
            OnPropertyChanged();
        }
    }

    public View? CurrentContent
    {
        get => currentContent;
        private set
        {
            if (currentContent == value)
            {
                return;
            }

            currentContent = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsContentVisible));
        }
    }

    public bool IsMenuVisible
    {
        get => isMenuVisible;
        private set
        {
            if (isMenuVisible == value)
            {
                return;
            }

            isMenuVisible = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsContentVisible));
        }
    }

    public bool IsContentVisible => !IsMenuVisible && CurrentContent is not null;

    private void ShowMenu()
    {
        CurrentContent = null;
        SelectedMode = null;
        IsMenuVisible = true;
    }

    private void SelectMode(PasswordModeOption? option)
    {
        if (option is null)
        {
            return;
        }

        SelectedMode = option;
        CurrentContent = option.CreateView();
        IsMenuVisible = false;
    }

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public class PasswordModeOption
{
    public PasswordModeOption(string title, string description, Func<ContentView> contentFactory, string? icon = null)
    {
        Title = title;
        Description = description;
        ContentFactory = contentFactory;
        Icon = icon;
    }

    public string Title { get; }

    public string Description { get; }

    public string? Icon { get; }

    private Func<ContentView> ContentFactory { get; }

    public ContentView CreateView() => ContentFactory();
}
