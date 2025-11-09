using System;
using Microsoft.Maui.Controls;
using PasswordModeOption = Password_Phrase_Producer.PasswordModeOption;

namespace Password_Phrase_Producer.Views;

public partial class ModeHostPage : ContentPage
{
    public ModeHostPage(PasswordModeOption option)
    {
        InitializeComponent();
        BindingContext = option;
        Title = option.Title;
        var contentView = option.CreateView();
        ContentHost.Content = new PasswordGeneratorHostView(contentView);
    }

    private async void OnBackTapped(object? sender, TappedEventArgs e)
    {
        await Shell.Current.GoToAsync("//home");
    }

    private void OnOpenMenuTapped(object? sender, TappedEventArgs e)
    {
        if (Shell.Current is not null)
        {
            Shell.Current.FlyoutIsPresented = true;
        }
    }
}
