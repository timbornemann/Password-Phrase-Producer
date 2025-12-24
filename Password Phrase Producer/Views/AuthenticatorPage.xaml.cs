using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.ViewModels;

namespace Password_Phrase_Producer.Views;

public partial class AuthenticatorPage : ContentPage
{
    private readonly AuthenticatorViewModel _viewModel;
    private readonly TotpEncryptionService _encryptionService;

    public AuthenticatorPage(AuthenticatorViewModel viewModel, TotpEncryptionService encryptionService)
    {
        InitializeComponent();
        BindingContext = _viewModel = viewModel;
        _encryptionService = encryptionService;
    }

    private void OnOpenMenuTapped(object sender, TappedEventArgs e)
    {
        // Match Vault behavior: open Flyout menu
        if (Shell.Current != null)
        {
            Shell.Current.FlyoutIsPresented = true;
        }
    }

    private async void OnBackTapped(object? sender, TappedEventArgs e)
    {
        if (Shell.Current is not null)
        {
            await Shell.Current.GoToAsync("//home");
        }
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        
        // Check if authenticator needs to be unlocked
        if (!_encryptionService.IsUnlocked)
        {
            var pinPage = Application.Current?.MainPage?.Handler?.MauiContext?.Services.GetService<AuthenticatorPinPage>();
            if (pinPage != null)
            {
                await Navigation.PushModalAsync(pinPage);
            }
        }
        
        // Only activate if unlocked
        if (_encryptionService.IsUnlocked)
        {
            _viewModel.Activate();
        }
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _viewModel.Deactivate();
    }
}
