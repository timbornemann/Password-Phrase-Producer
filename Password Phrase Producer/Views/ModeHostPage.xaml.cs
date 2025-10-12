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
        ContentHost.Content = option.CreateView();
    }

    private async void OnBackClicked(object? sender, EventArgs e)
    {
        await Shell.Current.GoToAsync("//home");
    }
}
