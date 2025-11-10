using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Graphics;
using Microsoft.Maui.Controls.Shapes;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Vault;
using Password_Phrase_Producer.Windows.PasswordGenerationWindows;

namespace Password_Phrase_Producer.Views;

public class PasswordGeneratorHostView : ContentView
{
    private readonly Button _addToVaultButton;
    private readonly IPasswordResultProvider? _resultProvider;
    private PasswordVaultService? _vaultService;

    public PasswordGeneratorHostView(View content)
    {
        ArgumentNullException.ThrowIfNull(content);

        _resultProvider = content as IPasswordResultProvider ?? FindResultProvider(content);
        _vaultService = ResolveVaultService();

        _addToVaultButton = CreateAddToVaultButton();

        var layout = new Grid
        {
            RowSpacing = 24,
            RowDefinitions =
            {
                new RowDefinition { Height = GridLength.Star },
                new RowDefinition { Height = GridLength.Auto }
            }
        };

        layout.Children.Add(content);
        Grid.SetRow(content, 0);

        var actionContainer = CreateActionContainer(_addToVaultButton);

        if (content is IPasswordGeneratorActionHost actionHost && actionHost.TrySetAddToVaultAction(actionContainer))
        {
            layout.RowDefinitions.Clear();
            layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Star });
        }
        else
        {
            layout.Children.Add(actionContainer);
            Grid.SetRow(actionContainer, 1);
        }

        Content = layout;

        UpdateButtonState();

        if (_resultProvider is not null)
        {
            _resultProvider.PasswordGenerated += OnPasswordGenerated;
            _resultProvider.PasswordCleared += OnPasswordCleared;
        }
    }

    protected override void OnParentSet()
    {
        base.OnParentSet();

        if (Parent is null)
        {
            DetachEvents();
        }
    }

    private Button CreateAddToVaultButton()
    {
        var button = new Button
        {
            Text = "Zum Tresor hinzufügen",
            HorizontalOptions = LayoutOptions.Fill,
            IsEnabled = false
        };

        if (Application.Current?.Resources.TryGetValue("PrimaryActionButtonStyle", out var styleObj) == true && styleObj is Style style)
        {
            button.Style = style;
        }

        button.Clicked += OnAddToVaultClicked;

        return button;
    }

    private View CreateActionContainer(Button button)
    {
        var border = new Border
        {
            StrokeThickness = 0,
            BackgroundColor = Color.FromArgb("#1F2438"),
            Padding = new Thickness(18, 16),
            StrokeShape = new RoundRectangle { CornerRadius = 20 }
        };

        border.Content = button;
        return border;
    }

    private void OnPasswordGenerated(object? sender, string password)
    {
        UpdateButtonState();
    }

    private void OnPasswordCleared(object? sender, EventArgs e)
    {
        UpdateButtonState();
    }

    private void UpdateButtonState()
    {
        var hasPassword = !string.IsNullOrWhiteSpace(_resultProvider?.LastGeneratedPassword);
        var canUseVault = GetVaultService() is not null;
        _addToVaultButton.IsEnabled = hasPassword && canUseVault;
    }

    private async void OnAddToVaultClicked(object? sender, EventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_resultProvider?.LastGeneratedPassword))
        {
            return;
        }

        var vaultService = GetVaultService();

        if (vaultService is null)
        {
            await ShowAlert("Tresor nicht verfügbar", "Der Tresor-Dienst konnte nicht geladen werden.");
            return;
        }

        var password = _resultProvider.LastGeneratedPassword!;

        if (!await vaultService.HasMasterPasswordAsync())
        {
            await PromptToCreateVault();
            return;
        }

        if (!vaultService.IsUnlocked)
        {
            var pendingRequest = VaultNavigationCoordinator.SetPendingPassword(password);

            var shell = Shell.Current;
            if (shell is null)
            {
                VaultNavigationCoordinator.ClearPendingRequest(pendingRequest.Id);
                await ShowAlert("Navigation nicht verfügbar", "Der Tresor konnte nicht geöffnet werden.");
                return;
            }

            try
            {
                await shell.GoToAsync("//vault");
            }
            catch (Exception ex)
            {
                VaultNavigationCoordinator.ClearPendingRequest(pendingRequest.Id);
                await ShowAlert("Navigation fehlgeschlagen", $"Der Tresor konnte nicht geöffnet werden: {ex.Message}");
            }

            return;
        }

        await AddPasswordToVaultAsync(password, vaultService);
    }

    private async Task AddPasswordToVaultAsync(string password, PasswordVaultService vaultService)
    {
        var navigation = Application.Current?.MainPage?.Navigation;
        if (navigation is null)
        {
            await ShowAlert("Navigation nicht verfügbar", "Der Tresor-Editor konnte nicht geöffnet werden.");
            return;
        }

        var entry = new PasswordVaultEntry
        {
            Password = password
        };

        var availableCategories = await LoadAvailableCategoriesAsync(vaultService);

        var result = await VaultEntryEditorPage.ShowAsync(navigation, entry, "Passwort zum Tresor hinzufügen", availableCategories);

        if (result is null)
        {
            return;
        }

        try
        {
            await vaultService.AddOrUpdateEntryAsync(result);
        }
        catch (Exception ex)
        {
            await ShowAlert("Fehler", $"Der Eintrag konnte nicht gespeichert werden: {ex.Message}");
            return;
        }

        await ShowAlert("Gespeichert", "Das Passwort wurde erfolgreich im Tresor abgelegt.");
    }

    private async Task PromptToCreateVault()
    {
        var mainPage = Application.Current?.MainPage;
        if (mainPage is null)
        {
            return;
        }

        var createVault = await mainPage.DisplayAlert(
            "Tresor benötigt",
            "Du musst zuerst einen Tresor anlegen, bevor du Passwörter speichern kannst.",
            "Tresor erstellen",
            "Abbrechen");

        if (createVault)
        {
            if (Shell.Current is not null)
            {
                await Shell.Current.GoToAsync("//vault");
            }
        }
    }

    private async Task ShowAlert(string title, string message)
    {
        var mainPage = Application.Current?.MainPage;
        if (mainPage is not null)
        {
            await mainPage.DisplayAlert(title, message, "OK");
        }
    }

    private async Task<string[]> LoadAvailableCategoriesAsync(PasswordVaultService vaultService)
    {
        try
        {
            var entries = await vaultService.GetEntriesAsync();
            return entries
                .Select(entry => entry.Category)
                .Where(category => !string.IsNullOrWhiteSpace(category))
                .Distinct(StringComparer.CurrentCultureIgnoreCase)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private void DetachEvents()
    {
        if (_resultProvider is not null)
        {
            _resultProvider.PasswordGenerated -= OnPasswordGenerated;
            _resultProvider.PasswordCleared -= OnPasswordCleared;
        }

        _addToVaultButton.Clicked -= OnAddToVaultClicked;
    }

    private static IPasswordResultProvider? FindResultProvider(object element)
    {
        if (element is IPasswordResultProvider provider)
        {
            return provider;
        }

        if (element is Element view)
        {
            foreach (var child in view.LogicalChildren)
            {
                if (child is IPasswordResultProvider childProvider)
                {
                    return childProvider;
                }

                var descendantProvider = FindResultProvider(child);
                if (descendantProvider is not null)
                {
                    return descendantProvider;
                }
            }
        }

        return null;
    }

    private PasswordVaultService? GetVaultService()
    {
        if (_vaultService is not null)
        {
            return _vaultService;
        }

        _vaultService = ResolveVaultService();
        return _vaultService;
    }

    private static PasswordVaultService? ResolveVaultService()
    {
        try
        {
            return Application.Current?.Handler?.MauiContext?.Services.GetService<PasswordVaultService>();
        }
        catch
        {
            return null;
        }
    }
}

public interface IPasswordResultProvider
{
    event EventHandler<string> PasswordGenerated;

    event EventHandler PasswordCleared;

    string? LastGeneratedPassword { get; }
}
