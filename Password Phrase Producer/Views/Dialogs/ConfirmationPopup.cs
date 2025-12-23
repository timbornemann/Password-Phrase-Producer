using System;
using CommunityToolkit.Maui.Views;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Controls.Shapes;
using Microsoft.Maui.Graphics;

namespace Password_Phrase_Producer.Views.Dialogs;

/// <summary>
/// A standardized confirmation popup with consistent design system styling.
/// </summary>
public sealed class ConfirmationPopup : Popup
{
    // Design System Colors
    private static readonly Color BackgroundCard = Color.FromArgb("#1B2036");
    private static readonly Color BackgroundButton = Color.FromArgb("#1F2338");
    private static readonly Color BackgroundButtonPrimary = Color.FromArgb("#4A5CFF");
    private static readonly Color BackgroundButtonDestructive = Color.FromArgb("#3B2232");
    private static readonly Color TextPrimary = Colors.White;
    private static readonly Color TextSecondary = Color.FromArgb("#E8EBFF");
    private static readonly Color TextTertiary = Color.FromArgb("#9EA3C4");

    public ConfirmationPopup(string title, string message, string confirmText, string cancelText, bool confirmIsDestructive = false)
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

        var buttonGrid = new Grid
        {
            ColumnDefinitions =
            {
                new ColumnDefinition { Width = GridLength.Star },
                new ColumnDefinition { Width = GridLength.Star }
            },
            ColumnSpacing = 12
        };

        var cancelButton = CreateActionButton(cancelText, BackgroundButton, TextSecondary, () => Close(false));
        buttonGrid.Children.Add(cancelButton);

        var confirmColor = confirmIsDestructive ? BackgroundButtonDestructive : BackgroundButtonPrimary;
        var confirmButton = CreateActionButton(confirmText, confirmColor, TextPrimary, () => Close(true));
        Grid.SetColumn(confirmButton, 1);
        Grid.SetRow(confirmButton, 0);
        buttonGrid.Children.Add(confirmButton);

        var cardLayout = new VerticalStackLayout
        {
            Spacing = 16,
            Children =
            {
                titleLabel,
                messageLabel,
                buttonGrid
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