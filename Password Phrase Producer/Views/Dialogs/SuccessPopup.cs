using System;
using CommunityToolkit.Maui.Views;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Controls.Shapes;
using Microsoft.Maui.Graphics;

namespace Password_Phrase_Producer.Views.Dialogs;

/// <summary>
/// A standardized success popup with consistent design system styling.
/// </summary>
public sealed class SuccessPopup : Popup
{
    // Design System Colors
    private static readonly Color BackgroundCard = Color.FromArgb("#1B2036");
    private static readonly Color BackgroundButtonPrimary = Color.FromArgb("#4A5CFF");
    private static readonly Color TextPrimary = Colors.White;
    private static readonly Color TextTertiary = Color.FromArgb("#9EA3C4");

    public SuccessPopup(string title, string message, string okText = "OK")
    {
        Color = Color.FromRgba(0, 0, 0, 0.65);
        CanBeDismissedByTappingOutsideOfPopup = false;

        var titleLabel = new Label
        {
            Text = title,
            FontSize = 18,
            FontAttributes = FontAttributes.Bold,
            TextColor = TextPrimary
        };

        var messageLabel = new Label
        {
            Text = message,
            FontSize = 14,
            TextColor = TextTertiary,
            LineBreakMode = LineBreakMode.WordWrap
        };

        var okButton = CreateActionButton(okText, BackgroundButtonPrimary, TextPrimary, () => Close(true));

        var cardLayout = new VerticalStackLayout
        {
            Spacing = 16,
            Children =
            {
                titleLabel,
                messageLabel,
                okButton
            }
        };

        var card = new Border
        {
            BackgroundColor = BackgroundCard,
            StrokeShape = new RoundRectangle { CornerRadius = 16 },
            StrokeThickness = 0,
            Padding = new Thickness(20, 20),
            Content = cardLayout
        };

        card.Shadow = new Shadow
        {
            Brush = new SolidColorBrush(Color.FromArgb("#25000000")),
            Radius = 12,
            Offset = new Point(0, 6)
        };

        Content = new Grid
        {
            HorizontalOptions = LayoutOptions.Fill,
            VerticalOptions = LayoutOptions.Fill,
            Children =
            {
                new Grid
                {
                    Padding = new Thickness(24),
                    HorizontalOptions = LayoutOptions.Fill,
                    VerticalOptions = LayoutOptions.Center,
                    Children = { card }
                }
            }
        };
    }

    private static View CreateActionButton(string text, Color background, Color textColor, Action onClicked)
    {
        var label = new Label
        {
            Text = text,
            FontSize = 14,
            FontAttributes = FontAttributes.Bold,
            TextColor = textColor,
            HorizontalTextAlignment = TextAlignment.Center,
            VerticalTextAlignment = TextAlignment.Center
        };

        var button = new Border
        {
            BackgroundColor = background,
            StrokeThickness = 0,
            StrokeShape = new RoundRectangle { CornerRadius = 12 },
            Padding = new Thickness(14, 12),
            Content = label
        };

        button.GestureRecognizers.Add(new TapGestureRecognizer
        {
            Command = new Command(onClicked)
        });

        return button;
    }
}

