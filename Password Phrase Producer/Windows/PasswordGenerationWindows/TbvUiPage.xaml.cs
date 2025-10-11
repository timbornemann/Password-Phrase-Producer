using System;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.PasswordGenerationTechniques.TbvTechniques;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class TbvUiPage : ContentView
{
    private readonly Itbv tbv;

    public TbvUiPage(Itbv itbv)
    {
        InitializeComponent();
        tbv = itbv;
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        var password = passwordEntry.Text;

        if (string.IsNullOrWhiteSpace(password))
        {
            resultEntry.Text = string.Empty;
            return;
        }

        bool c1 = int.TryParse(code1Entry.Text, out var code1);
        bool c2 = int.TryParse(code2Entry.Text, out var code2);
        bool c3 = int.TryParse(code3Entry.Text, out var code3);

        if (c1 && c2 && c3)
        {
            string result = tbv.GeneratePassword(password, code1, code2, code3);
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
