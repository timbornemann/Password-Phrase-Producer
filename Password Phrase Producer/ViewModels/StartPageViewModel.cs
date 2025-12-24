using System.Collections.ObjectModel;
using System.Linq;
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
        FeaturedMode = ModeOptions.FirstOrDefault();
        NavigateToModeCommand = new Command<PasswordModeOption>(NavigateToMode);
        NavigateToVaultCommand = new Command(NavigateToVault);
        NavigateToGenerationCommand = new Command(NavigateToGeneration);
        NavigateToAuthenticatorCommand = new Command(NavigateToAuthenticator);
    }

    public ObservableCollection<PasswordModeOption> ModeOptions { get; }

    public PasswordModeOption? FeaturedMode { get; }

    public ICommand NavigateToModeCommand { get; }
    public ICommand NavigateToVaultCommand { get; }
    public ICommand NavigateToGenerationCommand { get; }
    public ICommand NavigateToAuthenticatorCommand { get; }

    private async void NavigateToMode(PasswordModeOption? option)
    {
        if (option is null)
        {
            return;
        }

        await Shell.Current.GoToAsync($"//{option.Route}/{option.ContentRoute}");
    }

    private async void NavigateToVault()
    {
        // Navigate to the Vault page (defined in AppShell with route 'vault')
        await Shell.Current.GoToAsync("//vault");
    }

    private async void NavigateToGeneration()
    {
        // Navigate to the Generation Overview page
        await Shell.Current.GoToAsync("generation");
    }

    private async void NavigateToAuthenticator()
    {
        // Navigate to the Authenticator page (defined in AppShell with route 'authenticator')
        await Shell.Current.GoToAsync("//authenticator");
    }
}
