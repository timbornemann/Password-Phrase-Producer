using System;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.ViewModels;

namespace Password_Phrase_Producer.Views;

public partial class GenerationMethodsPage : ContentPage
{
    public GenerationMethodsPage()
    {
        InitializeComponent();
        BindingContext = new StartPageViewModel();
    }

    private void OnOpenMenuTapped(object? sender, EventArgs e)
    {
        Shell.Current.FlyoutIsPresented = true;
    }

    private async void OnBackTapped(object? sender, EventArgs e)
    {
        await Shell.Current.GoToAsync("//home");
    }

    protected override bool OnBackButtonPressed()
    {
        Dispatcher.Dispatch(async () => await Shell.Current.GoToAsync("//home"));
        return true;
    }
}
