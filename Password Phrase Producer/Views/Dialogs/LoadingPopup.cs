using CommunityToolkit.Maui.Views;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Controls.Shapes;
using Microsoft.Maui.Graphics;
using Microsoft.Maui.Primitives;

namespace Password_Phrase_Producer.Views.Dialogs;

public class LoadingPopup : Popup
{
    public LoadingPopup(string message = "Bitte warten...")
    {
        CanBeDismissedByTappingOutsideOfPopup = false;
        Color = Colors.Transparent;

        var border = new Border
        {
            StrokeThickness = 0,
            BackgroundColor = Color.FromArgb("#1B2036"),
            StrokeShape = new RoundRectangle { CornerRadius = 12 },
            Padding = 24,
            HorizontalOptions = LayoutOptions.Center,
            VerticalOptions = LayoutOptions.Center,
            Content = new VerticalStackLayout
            {
                Spacing = 16,
                Children =
                {
                    new ActivityIndicator
                    {
                        IsRunning = true,
                        Color = Color.FromArgb("#4A5CFF"),
                        WidthRequest = 48,
                        HeightRequest = 48,
                        HorizontalOptions = LayoutOptions.Center
                    },
                    new Label
                    {
                        Text = message,
                        TextColor = Colors.White,
                        FontSize = 14,
                        HorizontalOptions = LayoutOptions.Center,
                        HorizontalTextAlignment = TextAlignment.Center
                    }
                }
            }
        };

        Content = border;
    }
}
