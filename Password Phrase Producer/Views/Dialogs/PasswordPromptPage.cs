using System;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Controls.Shapes;
using Microsoft.Maui.Graphics;

namespace Password_Phrase_Producer.Views.Dialogs;

/// <summary>
/// A standardized password prompt page with consistent design system styling.
/// </summary>
public sealed class PasswordPromptPage : ContentPage
{
    // Design System Colors
    private static readonly Color BackgroundCard = Color.FromArgb("#1B2036");
    private static readonly Color BackgroundInput = Color.FromArgb("#1F2338");
    private static readonly Color BackgroundButtonPrimary = Color.FromArgb("#4A5CFF");
    private static readonly Color BackgroundButtonSecondary = Color.FromArgb("#1F2338");
    private static readonly Color TextPrimary = Colors.White;
    private static readonly Color TextSecondary = Color.FromArgb("#E8EBFF");
    private static readonly Color TextTertiary = Color.FromArgb("#9EA3C4");
    private static readonly Color TextPlaceholder = Color.FromArgb("#7F85B2");

    private readonly TaskCompletionSource<string?> _taskCompletionSource = new();
    private readonly Entry _passwordEntry;

    public PasswordPromptPage(string title, string message, string acceptButtonText, string cancelButtonText)
    {
        Title = title;
        Shell.SetNavBarIsVisible(this, false);

        // Page background gradient
        Background = new LinearGradientBrush
        {
            StartPoint = new Point(0, 0),
            EndPoint = new Point(1, 1),
            GradientStops =
            {
                new GradientStop(Color.FromArgb("#101018"), 0),
                new GradientStop(Color.FromArgb("#141426"), 0.6f),
                new GradientStop(Color.FromArgb("#0F111A"), 1)
            }
        };

        var titleLabel = new Label
        {
            Text = title,
            FontSize = 18,
            FontAttributes = FontAttributes.Bold,
            TextColor = TextPrimary,
            HorizontalTextAlignment = TextAlignment.Center
        };

        var messageLabel = new Label
        {
            Text = message,
            FontSize = 14,
            TextColor = TextTertiary,
            HorizontalOptions = LayoutOptions.Fill,
            HorizontalTextAlignment = TextAlignment.Center,
            LineBreakMode = LineBreakMode.WordWrap,
            Margin = new Thickness(0, 0, 0, 8)
        };

        _passwordEntry = new Entry
        {
            Placeholder = "Passwort eingeben",
            PlaceholderColor = TextPlaceholder,
            TextColor = TextPrimary,
            BackgroundColor = BackgroundInput,
            IsPassword = true,
            Keyboard = Keyboard.Text,
            HorizontalOptions = LayoutOptions.Fill,
            HeightRequest = 40,
            FontSize = 14
        };

        var inputBorder = new Border
        {
            BackgroundColor = BackgroundInput,
            StrokeThickness = 0,
            Padding = new Thickness(12, 0),
            Content = _passwordEntry
        };
        inputBorder.StrokeShape = new RoundRectangle { CornerRadius = 12 };

        var acceptButton = new Button
        {
            Text = string.IsNullOrWhiteSpace(acceptButtonText) ? "OK" : acceptButtonText,
            BackgroundColor = BackgroundButtonPrimary,
            TextColor = TextPrimary,
            FontSize = 14,
            FontAttributes = FontAttributes.Bold,
            CornerRadius = 12,
            HeightRequest = 40,
            HorizontalOptions = LayoutOptions.Fill,
            Margin = new Thickness(0, 8, 0, 0)
        };
        acceptButton.Clicked += (_, _) => Complete(_passwordEntry.Text);

        var cancelButton = new Button
        {
            Text = string.IsNullOrWhiteSpace(cancelButtonText) ? "Abbrechen" : cancelButtonText,
            BackgroundColor = BackgroundButtonSecondary,
            TextColor = TextSecondary,
            FontSize = 14,
            CornerRadius = 12,
            HeightRequest = 40,
            HorizontalOptions = LayoutOptions.Fill
        };
        cancelButton.Clicked += (_, _) => Complete(null);

        var cardContent = new VerticalStackLayout
        {
            Spacing = 12,
            Children =
            {
                titleLabel,
                messageLabel,
                inputBorder,
                acceptButton,
                cancelButton
            }
        };

        var card = new Border
        {
            BackgroundColor = BackgroundCard,
            StrokeThickness = 0,
            Padding = new Thickness(20),
            Content = cardContent,
            MaximumWidthRequest = 360
        };
        card.StrokeShape = new RoundRectangle { CornerRadius = 16 };
        card.Shadow = new Shadow
        {
            Brush = new SolidColorBrush(Color.FromArgb("#25000000")),
            Radius = 12,
            Offset = new Point(0, 6)
        };

        Content = new Grid
        {
            Padding = new Thickness(24),
            HorizontalOptions = LayoutOptions.Fill,
            VerticalOptions = LayoutOptions.Fill,
            Children =
            {
                new Grid
                {
                    HorizontalOptions = LayoutOptions.Center,
                    VerticalOptions = LayoutOptions.Center,
                    Children = { card }
                }
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