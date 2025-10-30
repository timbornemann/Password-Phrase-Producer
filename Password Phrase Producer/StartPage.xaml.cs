using System;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.ViewModels;

namespace Password_Phrase_Producer;

public partial class StartPage : ContentPage
{
    public StartPage()
    {
        InitializeComponent();
        BindingContext = new StartPageViewModel();
        Loaded += OnPageLoaded;
        SizeChanged += OnPageSizeChanged;
    }

    private void OnOpenMenuTapped(object? sender, TappedEventArgs e)
    {
        if (Shell.Current is not null)
        {
            Shell.Current.FlyoutIsPresented = true;
        }
    }

    private void OnPageLoaded(object? sender, EventArgs e)
    {
        UpdateGridSpan();
    }

    private void OnPageSizeChanged(object? sender, EventArgs e)
    {
        UpdateGridSpan();
    }

    private void UpdateGridSpan()
    {
        if (ModeGridLayout is null)
        {
            return;
        }

        double availableWidth = Width;

        if (double.IsNaN(availableWidth) || availableWidth <= 0)
        {
            return;
        }

        if (PageContentLayout is not null)
        {
            availableWidth -= PageContentLayout.Padding.HorizontalThickness;
        }

        availableWidth = Math.Max(0, availableWidth);

        const double minTileWidth = 280;
        double spacing = ModeGridLayout.HorizontalItemSpacing;

        int columns = Math.Max(1, (int)Math.Floor((availableWidth + spacing) / (minTileWidth + spacing)));

        if (ModeGridLayout.Span != columns)
        {
            ModeGridLayout.Span = columns;
        }
    }
}
