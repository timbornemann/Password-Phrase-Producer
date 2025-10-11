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
        string password = passwordEntry?.Text ?? string.Empty;

        if (!string.IsNullOrWhiteSpace(password))
        {
            string result = hashBasedTechnique.GeneratePassword(password);
            if (resultEntry is not null)
            {
                resultEntry.Text = result;
            }
        }
        else
        {
            if (resultEntry is not null)
            {
                resultEntry.Text = string.Empty;
            }
        }
    }

    private async void OnCopyClicked(object sender, EventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(resultEntry?.Text))
        {
            await Clipboard.Default.SetTextAsync(resultEntry!.Text);
            var mainPage = Application.Current?.MainPage;
            if (mainPage is not null)
            {
                await mainPage.DisplayAlert("Info", "Password copied to clipboard", "OK");
            }
        }
    }
}
