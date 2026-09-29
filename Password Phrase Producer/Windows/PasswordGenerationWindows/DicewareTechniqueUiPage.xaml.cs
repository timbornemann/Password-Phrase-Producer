using System;
using Password_Phrase_Producer.PasswordGenerationTechniques.DicewareTechnique;
using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class DicewareTechniqueUiPage : PasswordGeneratorContentView
{
    private readonly IDicewareTechnique dicewareTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public DicewareTechniqueUiPage(IDicewareTechnique dicewareTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        RegisterAddToVaultHost(addToVaultHost);
        this.dicewareTechnique = dicewareTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        UpdateWordCountLabel();
        analysisPanel?.Reset();
    }

    private void OnWordCountChanged(object? sender, ValueChangedEventArgs e)
    {
        UpdateWordCountLabel();
    }

    private void UpdateWordCountLabel()
    {
        if (wordCountLabel is not null)
        {
            wordCountLabel.Text = $"Wörter: {GetWordCount()}";
        }
    }

    private int GetWordCount()
    {
        return wordCountSlider is null ? 6 : (int)Math.Round(wordCountSlider.Value);
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        int wordCount = GetWordCount();
        string seed = seedEntry?.Text ?? string.Empty;
        bool hasSeed = !string.IsNullOrWhiteSpace(seed);
        seedWarning.IsVisible = hasSeed;
        string result = dicewareTechnique.Generate(wordCount, hasSeed ? seed : null);

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

        if (hasSeed)
        {
            analysisPanel?.Reset();
        }
        else if (analysisPanel is not null)
        {
            var analysis = entropyAnalyzer.Analyze(result) with
            {
                Entropy = Math.Round(wordCount * Math.Log2(7776), 2),
                StrengthScore = wordCount >= 6 ? 100 : 0,
                StrengthLabel = wordCount >= 6 ? "Stark" : "Schwach",
                Suggestions = new[] { "Die Entropie basiert auf der zufälligen Wortauswahl. Das angehängte Prüfzeichen erhöht sie nicht." }
            };
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

            await Password_Phrase_Producer.Services.SensitiveClipboard.CopyAsync(resultEntry!.Text);
            await ToastService.ShowCopiedAsync("Passwort");
        }
    }
}
