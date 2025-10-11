using System.Collections.ObjectModel;
using System.Windows.Input;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Services;
using PasswordModeOption = Password_Phrase_Producer.PasswordModeOption;

namespace Password_Phrase_Producer.ViewModels;

public class StartPageViewModel
{
    public StartPageViewModel()
    {
        ModeOptions = new ObservableCollection<PasswordModeOption>(ModeCatalog.AllModes);
        NavigateToModeCommand = new Command<PasswordModeOption>(NavigateToMode);
    }

    public ObservableCollection<PasswordModeOption> ModeOptions { get; }

    public ICommand NavigateToModeCommand { get; }

    private async void NavigateToMode(PasswordModeOption? option)
    {
        if (option is null)
        {
            return;
        }

        await Shell.Current.GoToAsync($"//{option.Route}");
    }
}
