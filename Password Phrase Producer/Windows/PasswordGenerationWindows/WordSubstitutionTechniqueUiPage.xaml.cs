using System;
using Password_Phrase_Producer.PasswordGenerationTechniques.WordSubstitutionTechnique;
using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class WordSubstitutionTechniqueUiPage : PasswordGeneratorContentView
{
    private readonly IWordSubstitutionTechnique wordSubstitutionTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public WordSubstitutionTechniqueUiPage(IWordSubstitutionTechnique wordSubstitutionTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        RegisterAddToVaultHost(addToVaultHost);
        this.wordSubstitutionTechnique = wordSubstitutionTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        analysisPanel?.Reset();
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        string password = passwordEntry?.Text ?? string.Empty;

        if (!string.IsNullOrWhiteSpace(password))
        {
            bool useLeetSpeak = leetSpeakCheckBox?.IsChecked ?? true;
            bool useSymbols = symbolSubstitutionCheckBox?.IsChecked ?? true;

            string result = wordSubstitutionTechnique.GeneratePassword(password, useLeetSpeak, useSymbols);
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
            // Visual feedback
            if (sender is Button button)
            {
                await AnimateCopyButton(button);
            }

            await Clipboard.Default.SetTextAsync(resultEntry!.Text);
            await ToastService.ShowCopiedAsync("Passwort");
        }
    }
}

