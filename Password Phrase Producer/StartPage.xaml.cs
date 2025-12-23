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
    }

    private void OnOpenMenuTapped(object? sender, TappedEventArgs e)
    {
        if (Shell.Current is not null)
        {
            Shell.Current.FlyoutIsPresented = true;
        }
    }
}
