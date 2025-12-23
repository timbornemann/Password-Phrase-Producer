using System;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.ViewModels;

namespace Password_Phrase_Producer.Views;

public partial class GenerationMethodsPage : ContentPage
{
    public GenerationMethodsPage()
    {
        InitializeComponent();
        BindingContext = new StartPageViewModel(); // Reuse the existing ViewModel which has the modes
        Loaded += OnPageLoaded;
        SizeChanged += OnPageSizeChanged;
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

    private async void OnOpenMenuTapped(object? sender, EventArgs e)
    {
        Shell.Current.FlyoutIsPresented = true;
    }

    private async void OnBackTapped(object? sender, EventArgs e)
    {
        await Shell.Current.GoToAsync("..");
    }
}
