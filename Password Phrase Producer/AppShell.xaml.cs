using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Views;
using Microsoft.Extensions.DependencyInjection;
using PasswordPhraseProducer.Updates;

namespace Password_Phrase_Producer;

public partial class AppShell : Shell
{
    public AppShell()
    {
        InitializeComponent();
        var services = Application.Current!.Handler!.MauiContext!.Services;
        var updates = services.GetRequiredService<IAppUpdateService>();
        AppVersionLabel.Text = "Version " + services.GetRequiredService<InstalledApplication>().Version;
        UpdateHint.IsVisible = updates.State.Release is not null;
        // The shell may be recreated after login; unsubscribe when it leaves the visual tree.
        EventHandler changed = (_, _) => MainThread.BeginInvokeOnMainThread(() => UpdateHint.IsVisible = updates.State.Release is not null);
        updates.StateChanged += changed;
        Unloaded += (_, _) => updates.StateChanged -= changed;
        RegisterModeRoutes();

        // Register route for Generation Methods Page
        Routing.RegisterRoute("generation", typeof(GenerationMethodsPage));

        // Register settings route explicitly (not using DataTemplate)
        Routing.RegisterRoute("settings", typeof(SettingsPage));

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
        await GoToAsync("//home/settings");
    }
}
