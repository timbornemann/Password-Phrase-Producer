using System;
using Password_Phrase_Producer.PasswordGenerationTechniques.HashBasedTechniques;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class HachBasedTechniquesUiPage : PasswordGeneratorContentView
{
    private readonly IHashBasedTechniques hashBasedTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public HachBasedTechniquesUiPage(IHashBasedTechniques hashBasedTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        RegisterAddToVaultHost(addToVaultHost);
        this.hashBasedTechnique = hashBasedTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        analysisPanel?.Reset();
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

            UpdateGeneratedPassword(result);

            if (analysisPanel is not null)
            {
                var analysis = entropyAnalyzer.Analyze(result);
                analysisPanel.Update(analysis);
            }
        }
        else
        {
            if (resultEntry is not null)
            {
                resultEntry.Text = string.Empty;
            }

            analysisPanel?.Reset();
            UpdateGeneratedPassword(null);
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
