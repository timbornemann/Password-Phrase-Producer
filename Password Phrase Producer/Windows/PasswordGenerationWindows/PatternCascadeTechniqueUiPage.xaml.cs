using System;
using Password_Phrase_Producer.PasswordGenerationTechniques.PatternCascadeTechnique;
using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class PatternCascadeTechniqueUiPage : PasswordGeneratorContentView
{
    private readonly IPatternCascadeTechnique patternCascadeTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public PatternCascadeTechniqueUiPage(IPatternCascadeTechnique patternCascadeTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        RegisterAddToVaultHost(addToVaultHost);
        this.patternCascadeTechnique = patternCascadeTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        analysisPanel?.Reset();
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        string primary = primaryEntry?.Text ?? string.Empty;
        string secondary = secondaryEntry?.Text ?? string.Empty;
        string numeric = numericEntry?.Text ?? string.Empty;

        string result = patternCascadeTechnique.CreatePassword(primary, secondary, numeric);

        if (string.IsNullOrEmpty(result))
        {
            if (resultEntry is not null)
            {
                resultEntry.Text = string.Empty;
            }

            analysisPanel?.Reset();
            UpdateGeneratedPassword(null);
            return;
        }

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
