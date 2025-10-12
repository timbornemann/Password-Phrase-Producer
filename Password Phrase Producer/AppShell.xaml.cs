using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Views;

namespace Password_Phrase_Producer;

public partial class AppShell : Shell
{
    public AppShell()
    {
        InitializeComponent();
        BuildModeMenu();
    }

    private void BuildModeMenu()
    {
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

            flyoutItem.Items.Add(shellContent);
            Items.Add(flyoutItem);
        }
    }
}
