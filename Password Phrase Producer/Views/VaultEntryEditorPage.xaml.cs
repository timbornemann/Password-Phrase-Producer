using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Microsoft.Maui.Controls;
using Microsoft.Maui.ApplicationModel;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Views;

public partial class VaultEntryEditorPage : ContentPage
{
    private readonly TaskCompletionSource<PasswordVaultEntry?> _resultSource = new();
    private readonly List<string> _availableCategories;
    private Page? _modalHost;

    public VaultEntryEditorPage(PasswordVaultEntry entry, string title, IEnumerable<string> availableCategories)
    {
        ArgumentNullException.ThrowIfNull(entry);

        _availableCategories = NormalizeCategories(availableCategories);
        CategorySuggestions = new ObservableCollection<string>();

        InitializeComponent();
        BindingContext = entry;
        Title = title;
        UpdateCategorySuggestions(entry.Category, false);
    }

    public Task<PasswordVaultEntry?> Result => _resultSource.Task;

    public ObservableCollection<string> CategorySuggestions { get; }

    public static async Task<PasswordVaultEntry?> ShowAsync(INavigation? navigation, PasswordVaultEntry entry, string title, IEnumerable<string> availableCategories)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var page = new VaultEntryEditorPage(entry, title, availableCategories);
        var (navigationHost, diagnostics) = ResolveNavigationHost(navigation);
        var modalHost = page.CreateModalHost();

        try
        {
            if (MainThread.IsMainThread)
            {
                await navigationHost.PushModalAsync(modalHost);
            }
            else
            {
                await MainThread.InvokeOnMainThreadAsync(() => navigationHost.PushModalAsync(modalHost));
            }
        }
        catch (NullReferenceException ex)
        {
            var message = $"Beim Öffnen des Tresor-Editors trat eine NullReferenceException im Navigationssystem auf.";
            Debug.WriteLine($"[VaultEntryEditorPage] {message}\n{ex}");
            throw CreateNavigationException(message, diagnostics, navigationHost, ex);
        }
        catch (Exception ex)
        {
            var message = $"PushModalAsync für den Tresor-Editor ist fehlgeschlagen ({navigationHost.GetType().FullName}). Grund: {ex.Message}";
            Debug.WriteLine($"[VaultEntryEditorPage] {message}\n{ex}");
            throw CreateNavigationException(message, diagnostics, navigationHost, ex);
        }

        return await page.Result.ConfigureAwait(false);
    }

    private static List<string> NormalizeCategories(IEnumerable<string>? availableCategories)
    {
        if (availableCategories is null)
        {
            return new List<string>();
        }

        return availableCategories
            .Where(category => !string.IsNullOrWhiteSpace(category))
            .Select(category => category.Trim())
            .Distinct(StringComparer.CurrentCultureIgnoreCase)
            .OrderBy(category => category, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
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
            var target = _modalHost ?? (Page)this;

            if (!navigationHost.ModalStack.Contains(target) && target is NavigationPage navigationPage)
            {
                var containedPage = navigationPage.Navigation?
                    .NavigationStack
                    .FirstOrDefault();

                containedPage ??= navigationPage.CurrentPage;
                if (containedPage == this && navigationHost.ModalStack.Contains(navigationPage))
                {
                    target = navigationPage;
                }
            }

            if (!navigationHost.ModalStack.Contains(target))
            {
                return;
            }

            if (!ReferenceEquals(navigationHost.ModalStack.LastOrDefault(), target))
            {
                Debug.WriteLine("[VaultEntryEditorPage] Das zu schließende Modal befindet sich nicht oben auf dem Stack. Abbruch, um unerwartete Navigation zu vermeiden.");
                return;
            }

            if (navigationHost.ModalStack.Contains(target))
            {
                await navigationHost.PopModalAsync().ConfigureAwait(false);
                _modalHost = null;
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

    private Page CreateModalHost()
    {
        NavigationPage.SetHasNavigationBar(this, false);
        NavigationPage.SetBackButtonTitle(this, string.Empty);

        var navigationPage = new NavigationPage(this)
        {
            Title = Title
        };

        _modalHost = navigationPage;
        return navigationPage;
    }

    private static (INavigation Host, string Diagnostics) ResolveNavigationHost(INavigation? navigation)
    {
        var candidateLog = new StringBuilder();
        INavigation? resolved = null;

        foreach (var candidate in GetNavigationCandidates(navigation))
        {
            INavigation? value = null;
            Exception? error = null;

            try
            {
                value = candidate.Resolver();
            }
            catch (Exception ex)
            {
                error = ex;
            }

            candidateLog.Append("• ")
                .Append(candidate.Description)
                .Append(": ")
                .AppendLine(value is null ? "null" : value.GetType().FullName);

            if (error is not null)
            {
                candidateLog.Append("    Ausnahme: ")
                    .Append(error.GetType().FullName)
                    .Append(": ")
                    .AppendLine(error.Message);
            }

            if (resolved is null && value is not null)
            {
                resolved = value;
            }
        }

        if (resolved is null)
        {
            var diagnostics = candidateLog.ToString();
            const string message = "Kein Navigationsstack verfügbar, um den Tresor-Editor zu öffnen.";

            throw CreateNavigationException(message, diagnostics, resolved, null);
        }

        var finalDiagnostics = BuildNavigationDiagnostics(resolved, navigation, candidateLog.ToString());
        return (resolved, finalDiagnostics);
    }

    private static IEnumerable<(string Description, Func<INavigation?> Resolver)> GetNavigationCandidates(INavigation? navigation)
    {
        yield return ("Shell.Current.CurrentPage.Navigation", () => Shell.Current?.CurrentPage?.Navigation);
        yield return ("Shell.Current.Navigation", () => Shell.Current?.Navigation);
        yield return ("Übergebene Navigation", () => navigation);
        yield return ("Application.Current.MainPage.Navigation", () => Application.Current?.MainPage?.Navigation);
    }

    private static string BuildNavigationDiagnostics(INavigation navigationHost, INavigation? requestedNavigation, string candidateLog)
    {
        var builder = new StringBuilder();

        if (!string.IsNullOrWhiteSpace(candidateLog))
        {
            builder.AppendLine("Untersuchte Navigationsquellen:")
                .Append(candidateLog);
        }

        builder.AppendLine("Verwendeter Navigator:")
            .Append("• Typ: ")
            .AppendLine(navigationHost.GetType().FullName);

        AppendNavigationStackInfo("NavigationStack", () => navigationHost.NavigationStack, builder);
        AppendNavigationStackInfo("ModalStack", () => navigationHost.ModalStack, builder);

        builder.AppendLine()
            .AppendLine("Shell-Zustand:");

        AppendStateValue(builder, "Shell.Current", () => Shell.Current);
        AppendStateValue(builder, "Shell.Current.CurrentPage", () => Shell.Current?.CurrentPage);
        AppendStateValue(builder, "Shell.Current.Navigation", () => Shell.Current?.Navigation);

        builder.AppendLine()
            .AppendLine("Application-Zustand:");

        AppendStateValue(builder, "Application.Current", () => Application.Current);
        AppendStateValue(builder, "Application.Current.MainPage", () => Application.Current?.MainPage);
        AppendStateValue(builder, "Angeforderter Navigator", () => requestedNavigation);

        return builder.ToString();
    }

    private static void AppendNavigationStackInfo(string name, Func<IReadOnlyList<Page>> stackAccessor, StringBuilder builder)
    {
        try
        {
            var stack = stackAccessor();
            builder.Append("• ")
                .Append(name)
                .Append(": Anzahl=")
                .Append(stack.Count)
                .AppendLine(stack.Count > 0
                    ? $", Top={stack[^1].GetType().FullName}"
                    : ", leer");
        }
        catch (Exception ex)
        {
            builder.Append("• ")
                .Append(name)
                .Append(": Fehler beim Abrufen: ")
                .Append(ex.GetType().FullName)
                .Append(": ")
                .AppendLine(ex.Message);
        }
    }

    private static InvalidOperationException CreateNavigationException(string message, string diagnostics, INavigation? navigationHost, Exception? inner)
    {
        var detailedMessage = new StringBuilder(message);
        if (!string.IsNullOrWhiteSpace(diagnostics))
        {
            detailedMessage.AppendLine()
                .AppendLine()
                .AppendLine("Diagnosedetails:")
                .Append(diagnostics);
        }

        if (navigationHost is not null)
        {
            detailedMessage.AppendLine()
                .Append("Verwendeter Navigator: ")
                .AppendLine(navigationHost.GetType().FullName);
        }

        var exception = inner is not null
            ? new InvalidOperationException(detailedMessage.ToString(), inner)
            : new InvalidOperationException(detailedMessage.ToString());

        if (!string.IsNullOrWhiteSpace(diagnostics))
        {
            exception.Data["NavigationDiagnostics"] = diagnostics;
        }

        return exception;
    }

    private static void AppendStateValue(StringBuilder builder, string label, Func<object?> valueAccessor)
    {
        try
        {
            var value = valueAccessor();
            var description = value switch
            {
                null => "null",
                Type type => type.FullName ?? type.Name,
                _ => value.GetType().FullName ?? value.ToString() ?? string.Empty
            };

            builder.Append("• ")
                .Append(label)
                .Append(": ")
                .AppendLine(description);
        }
        catch (Exception ex)
        {
            builder.Append("• ")
                .Append(label)
                .Append(": Fehler beim Abrufen: ")
                .Append(ex.GetType().FullName)
                .Append(": ")
                .AppendLine(ex.Message);
        }
    }
}
