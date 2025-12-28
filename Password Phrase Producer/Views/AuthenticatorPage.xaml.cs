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
            // Delay to ensure page is fully loaded and has MauiContext
            await Task.Delay(100);
            
            // Check if we still have a valid navigation context
            if (Navigation is null || Handler?.MauiContext is null)
            {
                // If navigation is not ready, try again after a short delay
                Dispatcher.Dispatch(async () =>
                {
                    await Task.Delay(200);
                    await ShowPinPageIfNeededAsync();
                });
            }
            else
            {
                await ShowPinPageIfNeededAsync();
            }
        }
        
        // Only activate if unlocked
        if (_encryptionService.IsUnlocked)
        {
            _viewModel.Activate();
        }
    }

    private async Task ShowPinPageIfNeededAsync()
    {
        // Double-check that we're still on this page and not unlocked
        if (_encryptionService.IsUnlocked || Navigation is null)
        {
            return;
        }

        try
        {
            // Use the MauiContext from this page, not MainPage
            var mauiContext = Handler?.MauiContext;
            if (mauiContext is null)
            {
                // Fallback to MainPage if this page doesn't have context yet
                mauiContext = Application.Current?.MainPage?.Handler?.MauiContext;
            }

            if (mauiContext?.Services is not null)
            {
                var pinPage = mauiContext.Services.GetService<AuthenticatorPinPage>();
                if (pinPage != null && Navigation is not null)
                {
                    await Navigation.PushModalAsync(pinPage);
                }
            }
        }
        catch (InvalidOperationException ex)
        {
            // MauiContext issue - log and try again after delay
            System.Diagnostics.Debug.WriteLine($"[AuthenticatorPage] MauiContext error: {ex.Message}");
            
            await Task.Delay(300);
            if (Navigation is not null && !_encryptionService.IsUnlocked)
            {
                try
                {
                    var mauiContext = Handler?.MauiContext ?? Application.Current?.MainPage?.Handler?.MauiContext;
                    if (mauiContext?.Services is not null)
                    {
                        var pinPage = mauiContext.Services.GetService<AuthenticatorPinPage>();
                        if (pinPage != null)
                        {
                            await Navigation.PushModalAsync(pinPage);
                        }
                    }
                }
                catch (Exception ex2)
                {
                    // Log but don't crash
                    System.Diagnostics.Debug.WriteLine($"[AuthenticatorPage] Failed to show pin page: {ex2.Message}");
                }
            }
        }
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _viewModel.Deactivate();
    }
}
