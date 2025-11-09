using System;
using Password_Phrase_Producer.PasswordGenerationTechniques.MirrorLockTechnique;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class MirrorTechniqueUiPage : PasswordGeneratorContentView
{
    private readonly IMirrorLockTechnique mirrorTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public MirrorTechniqueUiPage(IMirrorLockTechnique mirrorTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        this.mirrorTechnique = mirrorTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        analysisPanel?.Reset();
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        string input = inputEntry?.Text ?? string.Empty;
        string result = mirrorTechnique.CreatePassword(input);

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
            await Clipboard.Default.SetTextAsync(resultEntry!.Text);
            var mainPage = Application.Current?.MainPage;
            if (mainPage is not null)
            {
                await mainPage.DisplayAlert("Info", "Password copied to clipboard", "OK");
            }
        }
    }
}
