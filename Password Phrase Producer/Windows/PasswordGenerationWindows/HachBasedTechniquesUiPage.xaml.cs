using System;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.PasswordGenerationTechniques.HashBasedTechniques;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class HachBasedTechniquesUiPage : ContentView
{
    private readonly IHashBasedTechniques hashBasedTechnique;

    public HachBasedTechniquesUiPage(IHashBasedTechniques hashBasedTechnique)
    {
        InitializeComponent();
        this.hashBasedTechnique = hashBasedTechnique;
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        string password = passwordEntry.Text ?? string.Empty;

        if (!string.IsNullOrWhiteSpace(password))
        {
            string result = hashBasedTechnique.GeneratePassword(password);
            resultEntry.Text = result;
        }
        else
        {
            resultEntry.Text = string.Empty;
        }
    }

    private async void OnCopyClicked(object sender, EventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(resultEntry.Text))
        {
            await Clipboard.Default.SetTextAsync(resultEntry.Text);
            await Application.Current.MainPage.DisplayAlert("Info", "Password copied to clipboard", "OK");
        }
    }
}
