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
        return wordCountSlider is null ? 5 : (int)Math.Round(wordCountSlider.Value);
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        int wordCount = GetWordCount();
        string seed = seedEntry?.Text ?? string.Empty;
        string result = dicewareTechnique.Generate(wordCount, string.IsNullOrWhiteSpace(seed) ? null : seed);

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
