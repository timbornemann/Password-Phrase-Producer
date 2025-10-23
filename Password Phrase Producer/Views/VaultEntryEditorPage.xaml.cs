using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using Microsoft.Maui.Controls;
using Microsoft.Maui.ApplicationModel;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Views;

public partial class VaultEntryEditorPage : ContentPage
{
    private readonly TaskCompletionSource<PasswordVaultEntry?> _resultSource = new();
    private readonly List<string> _availableCategories;

    public VaultEntryEditorPage(PasswordVaultEntry entry, string title, IEnumerable<string> availableCategories)
    {
        ArgumentNullException.ThrowIfNull(entry);

        InitializeComponent();
        BindingContext = entry;
        Title = title;

        _availableCategories = availableCategories?
            .Where(category => !string.IsNullOrWhiteSpace(category))
            .Select(category => category.Trim())
            .Distinct(StringComparer.CurrentCultureIgnoreCase)
            .OrderBy(category => category, StringComparer.CurrentCultureIgnoreCase)
            .ToList()
            ?? new List<string>();

        CategorySuggestions = new ObservableCollection<string>();
        UpdateCategorySuggestions(entry.Category, false);
    }

    public Task<PasswordVaultEntry?> Result => _resultSource.Task;

    public ObservableCollection<string> CategorySuggestions { get; }

    public static async Task<PasswordVaultEntry?> ShowAsync(INavigation? navigation, PasswordVaultEntry entry, string title, IEnumerable<string> availableCategories)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var page = new VaultEntryEditorPage(entry, title, availableCategories);
        var diagnostics = new List<string>();
        INavigation? navigationHost = null;

        if (Shell.Current is null)
        {
            diagnostics.Add("Shell.Current ist null.");
        }
        else if (Shell.Current.Navigation is null)
        {
            diagnostics.Add("Shell.Current.Navigation ist null.");
        }
        else
        {
            navigationHost = Shell.Current.Navigation;
        }

        if (navigationHost is null)
        {
            if (navigation is not null)
            {
                navigationHost = navigation;
            }
            else
            {
                diagnostics.Add("Der übergebene Navigationsparameter war null.");
            }
        }

        if (navigationHost is null)
        {
            if (Application.Current?.MainPage is null)
            {
                diagnostics.Add("Application.Current.MainPage ist null.");
            }
            else if (Application.Current.MainPage.Navigation is null)
            {
                diagnostics.Add("Application.Current.MainPage.Navigation ist null.");
            }
            else
            {
                navigationHost = Application.Current.MainPage.Navigation;
            }
        }

        if (navigationHost is null)
        {
            var detail = diagnostics.Count == 0
                ? "Keine zusätzlichen Diagnosedetails verfügbar."
                : string.Join(" ", diagnostics);
            throw new InvalidOperationException($"Kein Navigationsstack verfügbar, um den Tresor-Editor zu öffnen. Diagnose: {detail}");
        }

        try
        {
            if (MainThread.IsMainThread)
            {
                await navigationHost.PushModalAsync(page);
            }
            else
            {
                await MainThread.InvokeOnMainThreadAsync(() => navigationHost.PushModalAsync(page));
            }
        }
        catch (Exception ex)
        {
            var message = $"PushModalAsync für den Tresor-Editor ist fehlgeschlagen ({navigationHost.GetType().FullName}). Grund: {ex.Message}";
            Debug.WriteLine($"[VaultEntryEditorPage] {message}\n{ex}");
            throw new InvalidOperationException(message, ex);
        }

        return await page.Result.ConfigureAwait(false);
    }

    private async void OnSaveClicked(object? sender, EventArgs e)
    {
        if (BindingContext is PasswordVaultEntry entry)
        {
            entry.ModifiedAt = DateTimeOffset.UtcNow;
            _resultSource.TrySetResult(entry);
        }

        await CloseAsync().ConfigureAwait(false);
    }

    private async void OnCancelClicked(object? sender, EventArgs e)
    {
        _resultSource.TrySetResult(null);
        await CloseAsync().ConfigureAwait(false);
    }

    private void OnCloseTapped(object? sender, TappedEventArgs e)
        => OnCancelClicked(sender, EventArgs.Empty);

    private void OnCategoryTextChanged(object? sender, TextChangedEventArgs e)
    {
        var isFocused = CategoryEntry?.IsFocused ?? false;
        UpdateCategorySuggestions(e.NewTextValue, isFocused);
    }

    private void OnCategoryEntryFocused(object? sender, FocusEventArgs e)
        => UpdateCategorySuggestions(CategoryEntry?.Text, true);

    private void OnCategoryEntryUnfocused(object? sender, FocusEventArgs e)
    {
        if (CategorySuggestionsView is not null)
        {
            CategorySuggestionsView.IsVisible = false;
        }
    }

    private void OnCategorySuggestionTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not string category)
        {
            return;
        }

        if (CategoryEntry is not null)
        {
            CategoryEntry.Text = category;
            CategoryEntry.CursorPosition = category.Length;
        }

        if (CategorySuggestionsView is not null)
        {
            CategorySuggestionsView.IsVisible = false;
        }
    }

    private void UpdateCategorySuggestions(string? query, bool showSuggestions)
    {
        if (_availableCategories.Count == 0)
        {
            CategorySuggestions.Clear();
            if (CategorySuggestionsView is not null)
            {
                CategorySuggestionsView.IsVisible = false;
            }
            return;
        }

        var normalizedQuery = query?.Trim() ?? string.Empty;

        var suggestions = string.IsNullOrEmpty(normalizedQuery)
            ? _availableCategories
            : _availableCategories.Where(category => category.Contains(normalizedQuery, StringComparison.CurrentCultureIgnoreCase));

        var distinctSuggestions = suggestions
            .Where(category => !string.Equals(category, normalizedQuery, StringComparison.CurrentCultureIgnoreCase))
            .Take(8)
            .ToList();

        CategorySuggestions.Clear();
        foreach (var suggestion in distinctSuggestions)
        {
            CategorySuggestions.Add(suggestion);
        }

        if (CategorySuggestionsView is not null)
        {
            CategorySuggestionsView.IsVisible = showSuggestions && CategorySuggestions.Count > 0;
        }
    }

    protected override bool OnBackButtonPressed()
    {
        if (!_resultSource.Task.IsCompleted)
        {
            _resultSource.TrySetResult(null);
        }

        return base.OnBackButtonPressed();
    }

    private async Task CloseAsync()
    {
        var navigationHost = Shell.Current?.Navigation
            ?? Navigation
            ?? Application.Current?.MainPage?.Navigation;

        if (navigationHost is null)
        {
            return;
        }

        async Task PopAsync()
        {
            if (navigationHost.ModalStack.Contains(this))
            {
                await navigationHost.PopModalAsync().ConfigureAwait(false);
            }
        }

        try
        {
            if (MainThread.IsMainThread)
            {
                await PopAsync().ConfigureAwait(false);
            }
            else
            {
                await MainThread.InvokeOnMainThreadAsync(PopAsync);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[VaultEntryEditorPage] Fehler beim Schließen des Editors: {ex}");
        }
    }
}
