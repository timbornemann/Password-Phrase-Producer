using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Graphics;
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

        var actionContainer = CreateActionContainer();
        layout.Children.Add(actionContainer);
        Grid.SetRow(actionContainer, 1);

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

    private View CreateActionContainer()
    {
        var border = new Border
        {
            StrokeThickness = 0,
            BackgroundColor = Color.FromArgb("#1F2438"),
            Padding = new Thickness(18, 16),
            StrokeShape = new RoundRectangle { CornerRadius = 20 }
        };

        _addToVaultButton = new Button
        {
            Text = "Zum Tresor hinzufügen",
            HorizontalOptions = LayoutOptions.Fill,
            IsEnabled = false
        };

        if (Application.Current?.Resources.TryGetValue("PrimaryActionButtonStyle", out var styleObj) == true && styleObj is Style style)
        {
            _addToVaultButton.Style = style;
        }

        _addToVaultButton.Clicked += OnAddToVaultClicked;

        border.Content = _addToVaultButton;
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
            await PromptToUnlockVault();
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

    private async Task PromptToUnlockVault()
    {
        var mainPage = Application.Current?.MainPage;
        if (mainPage is null)
        {
            return;
        }

        var navigateToVault = await mainPage.DisplayAlert(
            "Tresor gesperrt",
            "Bitte entsperre deinen Tresor, um Passwörter speichern zu können.",
            "Zum Tresor",
            "Abbrechen");

        if (navigateToVault)
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

        if (element is IElement view)
        {
            foreach (var child in view.FindDescendants())
            {
                if (child is IPasswordResultProvider childProvider)
                {
                    return childProvider;
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
