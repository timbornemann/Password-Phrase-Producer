using System;
using CommunityToolkit.Maui.Views;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Controls.Shapes;
using Microsoft.Maui.Graphics;

namespace Password_Phrase_Producer.Views.Dialogs;

/// <summary>
/// Popup that shows signed release notes as formatted Markdown.
/// </summary>
public sealed class ReleaseNotesPopup : Popup
{
    private static readonly Color BackgroundCard = Color.FromArgb("#171C21");
    private static readonly Color BackgroundButton = Color.FromArgb("#20272E");
    private static readonly Color BackgroundButtonPrimary = Color.FromArgb("#536D81");
    private static readonly Color TextPrimary = Colors.White;
    private static readonly Color TextSecondary = Color.FromArgb("#DDE2E6");
    private static readonly Color TextTertiary = Color.FromArgb("#9EAAB5");
    private static readonly Color TextError = Color.FromArgb("#E88B91");

    public ReleaseNotesPopup(string markdown, string? version, Uri? githubUri)
    {
        Color = Color.FromRgba(0, 0, 0, 0.65);
        CanBeDismissedByTappingOutsideOfPopup = true;

        var (cardWidth, notesHeight) = PopupSize();
        var layout = new VerticalStackLayout { Spacing = 16 };

        layout.Children.Add(new Label
        {
            Text = "Änderungshinweise",
            FontSize = 18,
            FontAttributes = FontAttributes.Bold,
            TextColor = TextPrimary
        });

        if (!string.IsNullOrWhiteSpace(version))
        {
            layout.Children.Add(new Label
            {
                Text = $"Version {version}",
                FontSize = 13,
                TextColor = TextTertiary,
                Margin = new Thickness(0, -8, 0, 0)
            });
        }

        layout.Children.Add(new ScrollView
        {
            HeightRequest = notesHeight,
            HorizontalOptions = LayoutOptions.Fill,
            Content = ReleaseNotesMarkdown.Render(markdown)
        });

        var errorLabel = new Label
        {
            Text = "Die Änderungshinweise konnten nicht im Browser geöffnet werden.",
            FontSize = 13,
            TextColor = TextError,
            LineBreakMode = LineBreakMode.WordWrap,
            IsVisible = false
        };
        layout.Children.Add(errorLabel);

        var showGitHub = githubUri is { IsAbsoluteUri: true } && githubUri.Scheme is "http" or "https";
        if (showGitHub)
        {
            var buttons = new Grid
            {
                ColumnDefinitions =
                {
                    new ColumnDefinition { Width = GridLength.Star },
                    new ColumnDefinition { Width = GridLength.Star }
                },
                ColumnSpacing = 12
            };
            buttons.Children.Add(CreateActionButton("Auf GitHub öffnen", BackgroundButton, TextSecondary, async () =>
            {
                try
                {
                    await Launcher.Default.OpenAsync(githubUri!);
                    errorLabel.IsVisible = false;
                }
                catch
                {
                    errorLabel.IsVisible = true;
                }
            }));
            var closeButton = CreateActionButton("Schließen", BackgroundButtonPrimary, TextPrimary, () => Close());
            Grid.SetColumn(closeButton, 1);
            buttons.Children.Add(closeButton);
            layout.Children.Add(buttons);
        }
        else
        {
            layout.Children.Add(CreateActionButton("Schließen", BackgroundButtonPrimary, TextPrimary, () => Close()));
        }

        var card = new Border
        {
            BackgroundColor = BackgroundCard,
            StrokeShape = new RoundRectangle { CornerRadius = 6 },
            StrokeThickness = 0,
            Padding = new Thickness(20, 20),
            WidthRequest = cardWidth,
            HorizontalOptions = LayoutOptions.Center,
            Content = layout
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

    private static (double CardWidth, double NotesHeight) PopupSize()
    {
        var display = DeviceDisplay.Current.MainDisplayInfo;
        var density = display.Density <= 0 ? 1 : display.Density;
        var screenWidth = display.Width / density;
        var screenHeight = display.Height / density;
        var cardWidth = Math.Min(560, Math.Max(280, screenWidth - 48));
        var notesHeight = Math.Clamp(screenHeight * 0.5, 160, 520);
        if (notesHeight + 220 > screenHeight)
            notesHeight = Math.Max(120, screenHeight - 220);
        return (cardWidth, notesHeight);
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
            StrokeShape = new RoundRectangle { CornerRadius = 4 },
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
