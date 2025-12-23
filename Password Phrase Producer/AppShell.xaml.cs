using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Views;

namespace Password_Phrase_Producer;

public partial class AppShell : Shell
{
    public AppShell()
    {
        InitializeComponent();
        RegisterModeRoutes();
        
        // Register route for Generation Methods Page
        Routing.RegisterRoute("generation", typeof(GenerationMethodsPage));

        // Hide default flyout icon on all platforms - we use custom menu buttons
        SetValue(Shell.FlyoutIconProperty, null);
    }

    private void RegisterModeRoutes()
    {
        // Register routes for all modes (hidden from flyout, accessible via GenerationMethodsPage)
        foreach (var mode in ModeCatalog.AllModes)
        {
            var shellContent = new ShellContent
            {
                Title = mode.Title,
                Route = mode.ContentRoute,
                ContentTemplate = new DataTemplate(() => new ModeHostPage(mode))
            };

            var flyoutItem = new FlyoutItem
            {
                Title = mode.Title,
                Route = mode.Route,
                FlyoutDisplayOptions = FlyoutDisplayOptions.AsSingleItem
            };
            
            // Hide from flyout menu - only accessible via navigation
            Shell.SetFlyoutItemIsVisible(flyoutItem, false);

            flyoutItem.Items.Add(shellContent);
            Items.Add(flyoutItem);
        }
    }

    private async void OnSettingsTapped(object? sender, EventArgs e)
    {
        // Close flyout and navigate to settings
        FlyoutIsPresented = false;
        await GoToAsync("//settings");
    }
}
