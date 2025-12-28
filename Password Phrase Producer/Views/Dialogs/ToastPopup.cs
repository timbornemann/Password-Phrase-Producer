using System;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Controls.Shapes;
using Microsoft.Maui.Graphics;

namespace Password_Phrase_Producer.Views.Dialogs;

/// <summary>
/// A toast notification that appears at the bottom of the screen without blocking the UI.
/// </summary>
public static class ToastPopup
{
    private static readonly Color BackgroundColor = Color.FromArgb("#1B2036");
    private static readonly Color TextColor = Color.FromArgb("#E8EBFF");
    private static readonly Color BorderColor = Color.FromArgb("#2A2F4A");

    /// <summary>
    /// Shows the toast and automatically dismisses it after the specified duration.
    /// </summary>
    public static async Task ShowAsync(Page page, string message, int durationMs = 2000)
    {
        if (page is null)
        {
            return;
        }

        // Find or create overlay grid
        var overlayGrid = GetOrCreateOverlayGrid(page);
        if (overlayGrid is null)
        {
            return;
        }

        // Ensure overlay grid has proper row structure for bottom positioning
        if (overlayGrid.RowDefinitions.Count == 1)
        {
            // Update to have two rows: one for content space, one for toast at bottom
            overlayGrid.RowDefinitions.Clear();
            overlayGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Star });
            overlayGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        }

        // Create toast border
        var label = new Label
        {
            Text = message,
            FontSize = 14,
            TextColor = TextColor,
            HorizontalTextAlignment = TextAlignment.Center,
            VerticalTextAlignment = TextAlignment.Center,
            Padding = new Thickness(20, 14)
        };

        var border = new Border
        {
            BackgroundColor = BackgroundColor,
            StrokeThickness = 1,
            Stroke = new SolidColorBrush(BorderColor),
            StrokeShape = new RoundRectangle { CornerRadius = 12 },
            Content = label,
            HorizontalOptions = LayoutOptions.Center,
            VerticalOptions = LayoutOptions.Start,
            Margin = new Thickness(20, 0, 20, 40),
            Opacity = 0,
            TranslationY = 20,
            Shadow = new Shadow
            {
                Brush = new SolidColorBrush(Color.FromArgb("#40000000")),
                Radius = 12,
                Offset = new Point(0, 4)
            },
            InputTransparent = true // Don't block touches
        };

        // Add to overlay grid in the bottom row
        Grid.SetRow(border, overlayGrid.RowDefinitions.Count - 1);
        overlayGrid.Children.Add(border);

        // Animate in
        await Task.WhenAll(
            border.FadeTo(1, 200, Easing.CubicOut),
            border.TranslateTo(0, 0, 200, Easing.CubicOut)
        );

        // Wait for duration
        await Task.Delay(durationMs);

        // Animate out
        await Task.WhenAll(
            border.FadeTo(0, 150, Easing.CubicIn),
            border.TranslateTo(0, 20, 150, Easing.CubicIn)
        );

        // Remove from layout
        overlayGrid.Children.Remove(border);
    }

    private static Grid? GetOrCreateOverlayGrid(Page page)
    {
        // Only work with ContentPage
        if (page is not ContentPage contentPage)
        {
            return null;
        }

        // Try to find existing overlay grid
        var rootContent = contentPage.Content;
        if (rootContent is Grid rootGrid)
        {
            // Check if there's already an overlay grid (last child that covers everything)
            foreach (var child in rootGrid.Children)
            {
                if (child is Grid existingOverlay && existingOverlay.ClassId == "ToastOverlay")
                {
                    // Ensure it has the proper row structure for bottom positioning
                    if (existingOverlay.RowDefinitions.Count == 1)
                    {
                        existingOverlay.RowDefinitions.Clear();
                        existingOverlay.RowDefinitions.Add(new RowDefinition { Height = GridLength.Star });
                        existingOverlay.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                    }
                    // Ensure overlay spans all rows of the root grid
                    Grid.SetRow(existingOverlay, 0);
                    Grid.SetRowSpan(existingOverlay, rootGrid.RowDefinitions.Count);
                    Grid.SetColumn(existingOverlay, 0);
                    Grid.SetColumnSpan(existingOverlay, rootGrid.ColumnDefinitions.Count);
                    return existingOverlay;
                }
            }

            // Create overlay grid with two rows: content space and bottom row for toast
            var newOverlay = new Grid
            {
                ClassId = "ToastOverlay",
                RowDefinitions = 
                { 
                    new RowDefinition { Height = GridLength.Star },
                    new RowDefinition { Height = GridLength.Auto }
                },
                ColumnDefinitions = { new ColumnDefinition { Width = GridLength.Star } },
                HorizontalOptions = LayoutOptions.Fill,
                VerticalOptions = LayoutOptions.Fill,
                BackgroundColor = Colors.Transparent,
                InputTransparent = true, // Don't block touches
                ZIndex = 1000 // Ensure it's on top
            };

            // Ensure overlay spans all rows of the root grid
            Grid.SetRow(newOverlay, 0);
            Grid.SetRowSpan(newOverlay, rootGrid.RowDefinitions.Count);
            Grid.SetColumn(newOverlay, 0);
            Grid.SetColumnSpan(newOverlay, rootGrid.ColumnDefinitions.Count);

            rootGrid.Children.Add(newOverlay);
            return newOverlay;
        }

        // If root is not a Grid, wrap it
        if (rootContent is View content)
        {
            var wrapperGrid = new Grid
            {
                RowDefinitions = { new RowDefinition { Height = GridLength.Star } },
                ColumnDefinitions = { new ColumnDefinition { Width = GridLength.Star } }
            };

            wrapperGrid.Children.Add(content);
            
            var newOverlay = new Grid
            {
                ClassId = "ToastOverlay",
                RowDefinitions = 
                { 
                    new RowDefinition { Height = GridLength.Star },
                    new RowDefinition { Height = GridLength.Auto }
                },
                ColumnDefinitions = { new ColumnDefinition { Width = GridLength.Star } },
                HorizontalOptions = LayoutOptions.Fill,
                VerticalOptions = LayoutOptions.Fill,
                BackgroundColor = Colors.Transparent,
                InputTransparent = true,
                ZIndex = 1000
            };

            wrapperGrid.Children.Add(newOverlay);
            contentPage.Content = wrapperGrid;
            return newOverlay;
        }

        return null;
    }
}

