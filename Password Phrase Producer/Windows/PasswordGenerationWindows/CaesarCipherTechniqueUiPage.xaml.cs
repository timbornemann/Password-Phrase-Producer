using System;
using Password_Phrase_Producer.PasswordGenerationTechniques.CaesarCipherTechnique;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class CaesarCipherTechniqueUiPage : PasswordGeneratorContentView
{
    private readonly ICaesarCipherTechnique caesarCipherTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public CaesarCipherTechniqueUiPage(ICaesarCipherTechnique caesarCipherTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        RegisterAddToVaultHost(addToVaultHost);
        this.caesarCipherTechnique = caesarCipherTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        analysisPanel?.Reset();
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        string password = passwordEntry?.Text ?? string.Empty;

        if (!string.IsNullOrWhiteSpace(password))
        {
            if (int.TryParse(shiftEntry?.Text, out int shift))
            {
                string result = caesarCipherTechnique.GeneratePassword(password, shift);
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
            var page = this.Window?.Page ?? Application.Current?.Windows[0]?.Page;
            if (page is not null)
            {
                await page.DisplayAlert("Info", "Password copied to clipboard", "OK");
            }
        }
    }
}

