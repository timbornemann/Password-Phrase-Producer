using System;
using CommunityToolkit.Maui.Views;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Graphics;

namespace Password_Phrase_Producer.Views.Dialogs;

public sealed class ConfirmationPopup : Popup
{
    public ConfirmationPopup(string title, string message, string confirmText, string cancelText, bool confirmIsDestructive = false)
    {
        BackgroundColor = Color.FromRgba(0, 0, 0, 0.65);
        CanBeDismissedByTappingOutside = false;

        var titleLabel = new Label
        {
            Text = title,
            FontSize = 18,
            FontAttributes = FontAttributes.Bold,
            TextColor = Colors.White
        };

        var messageLabel = new Label
        {
            Text = message,
            FontSize = 14,
            TextColor = Color.FromArgb("#B6BBE0"),
            LineBreakMode = LineBreakMode.WordWrap
        };

        var buttonGrid = new Grid
        {
            ColumnDefinitions =
            {
                new ColumnDefinition { Width = GridLength.Star },
                new ColumnDefinition { Width = GridLength.Star }
            },
            ColumnSpacing = 14
        };

        var cancelButton = CreateActionButton(cancelText, Color.FromArgb("#1A2038"), () => Close(false));
        buttonGrid.Children.Add(cancelButton);

        var confirmColor = confirmIsDestructive ? Color.FromArgb("#432028") : Color.FromArgb("#2C3A73");
        var confirmButton = CreateActionButton(confirmText, confirmColor, () => Close(true));
        buttonGrid.Children.Add(confirmButton, 1, 0);

        var cardLayout = new VerticalStackLayout
        {
            Spacing = 18,
            Children =
            {
                titleLabel,
                messageLabel,
                buttonGrid
            }
        };

        var card = new Border
        {
            BackgroundColor = Color.FromArgb("#1B2036"),
            StrokeShape = new RoundRectangle { CornerRadius = 28 },
            StrokeThickness = 0,
            Padding = new Thickness(24, 26),
            Content = cardLayout
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

    private static View CreateActionButton(string text, Color background, Action onClicked)
    {
        var label = new Label
        {
            Text = text,
            FontSize = 15,
            FontAttributes = FontAttributes.Bold,
            TextColor = Colors.White,
            HorizontalTextAlignment = TextAlignment.Center,
            VerticalTextAlignment = TextAlignment.Center
        };

        var button = new Border
        {
            BackgroundColor = background,
            StrokeThickness = 0,
            StrokeShape = new RoundRectangle { CornerRadius = 18 },
            Padding = new Thickness(16, 14),
            Content = label
        };

        button.GestureRecognizers.Add(new TapGestureRecognizer
        {
            Command = new Command(onClicked)
        });

        return button;
    }
}
