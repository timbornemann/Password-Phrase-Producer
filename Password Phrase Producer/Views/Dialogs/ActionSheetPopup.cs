using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Maui.Views;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Graphics;

namespace Password_Phrase_Producer.Views.Dialogs;

public sealed record ActionSheetPopupOption(string Id, string Title, string? Description = null, bool IsDestructive = false, bool IsSelected = false);

public sealed class ActionSheetPopup : Popup
{
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

        BackgroundColor = Color.FromRgba(0, 0, 0, 0.65);
        CanBeDismissedByTappingOutside = cancelText is not null;

        var contentStack = new VerticalStackLayout
        {
            Spacing = 18
        };

        if (!string.IsNullOrWhiteSpace(title))
        {
            contentStack.Children.Add(new Label
            {
                Text = title,
                FontSize = 18,
                FontAttributes = FontAttributes.Bold,
                TextColor = Colors.White
            });
        }

        if (!string.IsNullOrWhiteSpace(message))
        {
            contentStack.Children.Add(new Label
            {
                Text = message,
                FontSize = 14,
                TextColor = Color.FromArgb("#B6BBE0"),
                LineBreakMode = LineBreakMode.WordWrap
            });
        }

        foreach (var option in optionList)
        {
            contentStack.Children.Add(CreateOptionView(option));
        }

        var card = new Border
        {
            BackgroundColor = Color.FromArgb("#1B2036"),
            StrokeShape = new RoundRectangle { CornerRadius = 26 },
            StrokeThickness = 0,
            Padding = new Thickness(22, 22, 22, 24),
            Content = contentStack
        };

        var rootStack = new VerticalStackLayout
        {
            Spacing = 18,
            Margin = new Thickness(24, 0, 24, 36),
            HorizontalOptions = LayoutOptions.Fill,
            VerticalOptions = LayoutOptions.End
        };

        rootStack.Children.Add(card);

        if (!string.IsNullOrWhiteSpace(cancelText))
        {
            rootStack.Children.Add(CreateCancelButton(cancelText));
        }

        Content = new Grid
        {
            HorizontalOptions = LayoutOptions.Fill,
            VerticalOptions = LayoutOptions.Fill,
            Children =
            {
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
            FontSize = 16,
            FontAttributes = FontAttributes.Bold,
            TextColor = option.IsDestructive ? Color.FromArgb("#FF7474") : Colors.White
        };
        optionLayout.Children.Add(titleLabel);

        if (!string.IsNullOrWhiteSpace(option.Description))
        {
            optionLayout.Children.Add(new Label
            {
                Text = option.Description,
                FontSize = 13,
                TextColor = Color.FromArgb("#9EA3C4"),
                LineBreakMode = LineBreakMode.WordWrap
            }, 0, 1);
        }

        if (option.IsSelected)
        {
            var checkLabel = new Label
            {
                Text = "✓",
                FontSize = 16,
                TextColor = Color.FromArgb("#63F5A8"),
                HorizontalOptions = LayoutOptions.End,
                VerticalOptions = LayoutOptions.Start
            };
            optionLayout.Children.Add(checkLabel, 1, 0);
            Grid.SetRowSpan(checkLabel, string.IsNullOrWhiteSpace(option.Description) ? 1 : 2);
        }

        var optionBorder = new Border
        {
            BackgroundColor = option.IsSelected ? Color.FromArgb("#262D4A") : Color.FromArgb("#161B2F"),
            StrokeShape = new RoundRectangle { CornerRadius = 20 },
            StrokeThickness = 0,
            Padding = new Thickness(18, 14),
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
            BackgroundColor = Color.FromArgb("#161B2F"),
            StrokeShape = new RoundRectangle { CornerRadius = 20 },
            StrokeThickness = 0,
            Padding = new Thickness(18, 14),
            Content = new Label
            {
                Text = cancelText,
                FontSize = 16,
                TextColor = Colors.White,
                HorizontalTextAlignment = TextAlignment.Center
            }
        };

        cancelBorder.GestureRecognizers.Add(new TapGestureRecognizer
        {
            Command = new Command(() => Close(null))
        });

        return cancelBorder;
    }

    protected override void OnLightDismissed()
    {
        base.OnLightDismissed();

        if (_cancelText is not null)
        {
            Close(null);
        }
    }
}
