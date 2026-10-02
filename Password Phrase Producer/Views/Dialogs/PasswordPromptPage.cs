using System;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Controls.Shapes;
using Microsoft.Maui.Graphics;
using Password_Phrase_Producer.Views.Controls;

namespace Password_Phrase_Producer.Views.Dialogs;

/// <summary>
/// A standardized password prompt page with consistent design system styling.
/// </summary>
public sealed class PasswordPromptPage : ContentPage
{
    // Design System Colors
    private static readonly Color BackgroundCard = Color.FromArgb("#171C21");
    private static readonly Color BackgroundInput = Color.FromArgb("#20272E");
    private static readonly Color BackgroundButtonPrimary = Color.FromArgb("#536D81");
    private static readonly Color BackgroundButtonSecondary = Color.FromArgb("#20272E");
    private static readonly Color TextPrimary = Colors.White;
    private static readonly Color TextSecondary = Color.FromArgb("#DDE2E6");
    private static readonly Color TextTertiary = Color.FromArgb("#9EAAB5");
    private static readonly Color TextPlaceholder = Color.FromArgb("#8797A4");

    private readonly TaskCompletionSource<string?> _taskCompletionSource = new();
    private readonly Entry _passwordEntry;

    public PasswordPromptPage(string title, string message, string acceptButtonText, string cancelButtonText,
        bool showStrengthMeter = false)
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
                new GradientStop(Color.FromArgb("#0D1013"), 0),
                new GradientStop(Color.FromArgb("#11161A"), 0.6f),
                new GradientStop(Color.FromArgb("#0F1317"), 1)
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

        _passwordEntry = new FramedEntry
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

        var acceptButton = new Button
        {
            Text = string.IsNullOrWhiteSpace(acceptButtonText) ? "OK" : acceptButtonText,
            BackgroundColor = BackgroundButtonPrimary,
            TextColor = TextPrimary,
            FontSize = 14,
            FontAttributes = FontAttributes.Bold,
            CornerRadius = 4,
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
            CornerRadius = 4,
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
                _passwordEntry
            }
        };
        if (showStrengthMeter)
        {
            var meter = new PasswordStrengthMeter();
            _passwordEntry.TextChanged += (_, e) => meter.Password = e.NewTextValue;
            cardContent.Children.Add(meter);
        }
        cardContent.Children.Add(acceptButton);
        cardContent.Children.Add(cancelButton);

        var card = new Border
        {
            BackgroundColor = BackgroundCard,
            StrokeThickness = 0,
            Padding = new Thickness(20),
            Content = cardContent,
            MaximumWidthRequest = 360
        };
        card.StrokeShape = new RoundRectangle { CornerRadius = 6 };

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
        _passwordEntry.Text = string.Empty;
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
