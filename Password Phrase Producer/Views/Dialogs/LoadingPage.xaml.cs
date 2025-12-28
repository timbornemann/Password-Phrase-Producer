using Microsoft.Maui.Controls;

namespace Password_Phrase_Producer.Views.Dialogs;

public partial class LoadingPage : ContentPage
{
    public LoadingPage(string message = "Bitte warten...")
    {
        InitializeComponent();
        MessageLabel.Text = message;
    }

    // Prevent hardware back button from closing this modal
    protected override bool OnBackButtonPressed()
    {
        return true;
    }
}
