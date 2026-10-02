using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Maui.Views;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Controls.Shapes;
using Microsoft.Maui.Graphics;

namespace Password_Phrase_Producer.Views.Dialogs;

public sealed record ActionSheetPopupOption(string Id, string Title, string? Description = null, bool IsDestructive = false, bool IsSelected = false);

/// <summary>
/// A standardized action sheet popup with consistent design system styling.
/// </summary>
public sealed class ActionSheetPopup : Popup
{
    // Design System Colors
    private static readonly Color BackgroundCard = Color.FromArgb("#171C21");
    private static readonly Color BackgroundOption = Color.FromArgb("#20272E");
    private static readonly Color BackgroundOptionSelected = Color.FromArgb("#2B343D");
    private static readonly Color TextPrimary = Colors.White;
    private static readonly Color TextSecondary = Color.FromArgb("#DDE2E6");
    private static readonly Color TextTertiary = Color.FromArgb("#9EAAB5");
    private static readonly Color TextDestructive = Color.FromArgb("#E88B91");
    private static readonly Color AccentSuccess = Color.FromArgb("#69C49A");

    private readonly string? _cancelText;

    public ActionSheetPopup(string title, IEnumerable<ActionSheetPopupOption> options, string? message = null, string? cancelText = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        var optionList = options.ToList();
        if (optionList.Count == 0)
        {
            throw new ArgumentException("At least one option is required.", nameof(options));
        }

        _cancelText = cancelText;

        // Transparent background - no black overlay
        Color = Colors.Transparent;
        CanBeDismissedByTappingOutsideOfPopup = cancelText is not null;

        var contentStack = new VerticalStackLayout
        {
            Spacing = 12
        };

        if (!string.IsNullOrWhiteSpace(title))
        {
            contentStack.Children.Add(new Label
            {
                Text = title,
                FontSize = 18,
                FontAttributes = FontAttributes.Bold,
                TextColor = TextPrimary
            });
        }

        if (!string.IsNullOrWhiteSpace(message))
        {
            contentStack.Children.Add(new Label
            {
                Text = message,
                FontSize = 14,
                TextColor = TextTertiary,
                LineBreakMode = LineBreakMode.WordWrap
            });
        }

        foreach (var option in optionList)
        {
            contentStack.Children.Add(CreateOptionView(option));
        }

        var card = new Border
        {
            BackgroundColor = BackgroundCard,
            StrokeShape = new RoundRectangle { CornerRadius = 8 },
            StrokeThickness = 1,
            Stroke = new SolidColorBrush(Color.FromArgb("#313B44")),
            Padding = new Thickness(18, 18, 18, 22),
            Content = contentStack
        };

        var rootStack = new VerticalStackLayout
        {
            Spacing = 10,
            Margin = new Thickness(20, 0, 20, 32),
            HorizontalOptions = LayoutOptions.Fill,
            VerticalOptions = LayoutOptions.End
        };

        rootStack.Children.Add(card);

        if (!string.IsNullOrWhiteSpace(cancelText))
        {
            rootStack.Children.Add(CreateCancelButton(cancelText));
        }

        // Wrap in a Grid with subtle backdrop
        var backdrop = new BoxView
        {
            Color = Color.FromRgba(0, 0, 0, 0.4),
            HorizontalOptions = LayoutOptions.Fill,
            VerticalOptions = LayoutOptions.Fill
        };
        backdrop.GestureRecognizers.Add(new TapGestureRecognizer
        {
            Command = new Command(() =>
            {
                if (CanBeDismissedByTappingOutsideOfPopup)
                {
                    Close(null);
                }
            })
        });

        Content = new Grid
        {
            HorizontalOptions = LayoutOptions.Fill,
            VerticalOptions = LayoutOptions.Fill,
            Children =
            {
                backdrop,
                rootStack
            }
        };
    }

    private View CreateOptionView(ActionSheetPopupOption option)
    {
        var optionLayout = new Grid
        {
            ColumnDefinitions =
            {
                new ColumnDefinition { Width = GridLength.Star },
                new ColumnDefinition { Width = GridLength.Auto }
            },
            RowDefinitions =
            {
                new RowDefinition { Height = GridLength.Auto },
                new RowDefinition { Height = GridLength.Auto }
            },
            ColumnSpacing = 12
        };

        var titleLabel = new Label
        {
            Text = option.Title,
            FontSize = 15,
            FontAttributes = FontAttributes.Bold,
            TextColor = option.IsDestructive ? TextDestructive : TextPrimary
        };
        optionLayout.Children.Add(titleLabel);

        if (!string.IsNullOrWhiteSpace(option.Description))
        {
            var descriptionLabel = new Label
            {
                Text = option.Description,
                FontSize = 12,
                TextColor = TextTertiary,
                LineBreakMode = LineBreakMode.WordWrap
            };
            Grid.SetColumn(descriptionLabel, 0);
            Grid.SetRow(descriptionLabel, 1);
            optionLayout.Children.Add(descriptionLabel);
        }

        if (option.IsSelected)
        {
            var checkLabel = new Label
            {
                Text = "✓",
                FontSize = 15,
                FontAttributes = FontAttributes.Bold,
                TextColor = AccentSuccess,
                HorizontalOptions = LayoutOptions.End,
                VerticalOptions = LayoutOptions.Start
            };
            Grid.SetColumn(checkLabel, 1);
            Grid.SetRow(checkLabel, 0);
            optionLayout.Children.Add(checkLabel);
            Grid.SetRowSpan(checkLabel, string.IsNullOrWhiteSpace(option.Description) ? 1 : 2);
        }

        var optionBorder = new Border
        {
            BackgroundColor = option.IsSelected ? BackgroundOptionSelected : BackgroundOption,
            StrokeShape = new RoundRectangle { CornerRadius = 4 },
            StrokeThickness = 0,
            Padding = new Thickness(14, 12),
            Content = optionLayout
        };

        var capturedOption = option;
        optionBorder.GestureRecognizers.Add(new TapGestureRecognizer
        {
            Command = new Command(() => Close(capturedOption.Id))
        });

        return optionBorder;
    }

    private View CreateCancelButton(string cancelText)
    {
        var cancelBorder = new Border
        {
            BackgroundColor = BackgroundCard,
            StrokeShape = new RoundRectangle { CornerRadius = 6 },
            StrokeThickness = 1,
            Stroke = new SolidColorBrush(Color.FromArgb("#313B44")),
            Padding = new Thickness(16, 14),
            Content = new Label
            {
                Text = cancelText,
                FontSize = 15,
                FontAttributes = FontAttributes.Bold,
                TextColor = TextSecondary,
                HorizontalTextAlignment = TextAlignment.Center
            }
        };

        cancelBorder.GestureRecognizers.Add(new TapGestureRecognizer
        {
            Command = new Command(() => Close(null))
        });

        return cancelBorder;
    }
}