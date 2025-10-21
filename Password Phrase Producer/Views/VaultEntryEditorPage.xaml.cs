using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Views;

public partial class VaultEntryEditorPage : ContentPage
{
    private readonly TaskCompletionSource<PasswordVaultEntry?> _resultSource = new();
    private readonly List<string> _availableCategories;

    public VaultEntryEditorPage(PasswordVaultEntry entry, string title, IEnumerable<string> availableCategories)
    {
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
        var page = new VaultEntryEditorPage(entry, title, availableCategories);
        var navigationHost = navigation ?? Application.Current?.MainPage?.Navigation;
        if (navigationHost is null)
        {
            throw new InvalidOperationException("Kein Navigationsstack verfügbar.");
        }

        await navigationHost.PushModalAsync(page);
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
        => UpdateCategorySuggestions(e.NewTextValue, CategoryEntry.IsFocused);

    private void OnCategoryEntryFocused(object? sender, FocusEventArgs e)
        => UpdateCategorySuggestions(CategoryEntry.Text, true);

    private void OnCategoryEntryUnfocused(object? sender, FocusEventArgs e)
    {
        CategorySuggestionsView.IsVisible = false;
    }

    private void OnCategorySuggestionTapped(object? sender, TappedEventArgs e)
    {
        if (e.Parameter is not string category)
        {
            return;
        }

        CategoryEntry.Text = category;
        CategoryEntry.CursorPosition = category.Length;
        CategorySuggestionsView.IsVisible = false;
    }

    private void UpdateCategorySuggestions(string? query, bool showSuggestions)
    {
        if (_availableCategories.Count == 0)
        {
            CategorySuggestions.Clear();
            CategorySuggestionsView.IsVisible = false;
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

        CategorySuggestionsView.IsVisible = showSuggestions && CategorySuggestions.Count > 0;
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
        if (Navigation.ModalStack.Contains(this))
        {
            await Navigation.PopModalAsync().ConfigureAwait(false);
        }
    }
}
