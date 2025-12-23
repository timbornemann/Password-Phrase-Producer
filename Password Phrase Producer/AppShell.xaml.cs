using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Views;

namespace Password_Phrase_Producer;

public partial class AppShell : Shell
{
    public AppShell()
    {
        InitializeComponent();
        BuildModeMenu();
        
        // Hide default flyout icon on all platforms - we use custom menu buttons
        SetValue(Shell.FlyoutIconProperty, null);
    }

    private void BuildModeMenu()
    {
        var modeIcons = new[] { "🎲", "🔀", "🔢", "📝", "🔤", "💉", "🪞", "🔁", "📐", "🧩" };
        var iconIndex = 0;

        foreach (var mode in ModeCatalog.AllModes)
        {
            var icon = iconIndex < modeIcons.Length ? modeIcons[iconIndex] : "📦";
            iconIndex++;

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
                FlyoutIcon = icon,
                FlyoutDisplayOptions = FlyoutDisplayOptions.AsSingleItem
            };

            flyoutItem.Items.Add(shellContent);
            Items.Add(flyoutItem);
        }
    }
}
