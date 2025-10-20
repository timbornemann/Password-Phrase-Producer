using System;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;

namespace Password_Phrase_Producer.Views.Dialogs;

public sealed class PasswordPromptPage : ContentPage
{
    private readonly TaskCompletionSource<string?> _taskCompletionSource = new();
    private readonly Entry _passwordEntry;

    public PasswordPromptPage(string title, string message, string acceptButtonText, string cancelButtonText)
    {
        Title = title;

        var messageLabel = new Label
        {
            Text = message,
            HorizontalOptions = LayoutOptions.Fill,
            HorizontalTextAlignment = TextAlignment.Center,
            Margin = new Thickness(0, 0, 0, 12)
        };

        _passwordEntry = new Entry
        {
            Placeholder = string.Empty,
            IsPassword = true,
            Keyboard = Keyboard.Text,
            HorizontalOptions = LayoutOptions.Fill
        };

        var acceptButton = new Button
        {
            Text = string.IsNullOrWhiteSpace(acceptButtonText) ? "OK" : acceptButtonText,
            HorizontalOptions = LayoutOptions.Fill,
            Margin = new Thickness(0, 12, 0, 0)
        };
        acceptButton.Clicked += (_, _) => Complete(_passwordEntry.Text);

        var cancelButton = new Button
        {
            Text = string.IsNullOrWhiteSpace(cancelButtonText) ? "Abbrechen" : cancelButtonText,
            HorizontalOptions = LayoutOptions.Fill
        };
        cancelButton.Clicked += (_, _) => Complete(null);

        Content = new VerticalStackLayout
        {
            Padding = new Thickness(24),
            Spacing = 12,
            HorizontalOptions = LayoutOptions.Center,
            VerticalOptions = LayoutOptions.Center,
            Children =
            {
                messageLabel,
                _passwordEntry,
                acceptButton,
                cancelButton
            }
        };
    }

    public Task<string?> WaitForResultAsync() => _taskCompletionSource.Task;

    protected override void OnAppearing()
    {
        base.OnAppearing();
        _passwordEntry.Focus();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        if (!_taskCompletionSource.Task.IsCompleted)
        {
            _taskCompletionSource.TrySetResult(null);
        }
    }

    protected override bool OnBackButtonPressed()
    {
        if (!_taskCompletionSource.Task.IsCompleted)
        {
            _taskCompletionSource.TrySetResult(null);
        }

        return base.OnBackButtonPressed();
    }

    private void Complete(string? result)
    {
        if (_taskCompletionSource.Task.IsCompleted)
        {
            return;
        }

        _taskCompletionSource.TrySetResult(result);
    }
}
