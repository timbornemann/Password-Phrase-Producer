using System;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.PasswordGenerationTechniques.PatternCascadeTechnique;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class PatternCascadeTechniqueUiPage : ContentView
{
    private readonly IPatternCascadeTechnique patternCascadeTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public PatternCascadeTechniqueUiPage(IPatternCascadeTechnique patternCascadeTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
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
            return;
        }

        if (resultEntry is not null)
        {
            resultEntry.Text = result;
        }

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
            await Clipboard.Default.SetTextAsync(resultEntry!.Text);
            var mainPage = Application.Current?.MainPage;
            if (mainPage is not null)
            {
                await mainPage.DisplayAlert("Info", "Password copied to clipboard", "OK");
            }
        }
    }
}
