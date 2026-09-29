using System;
using Password_Phrase_Producer.PasswordGenerationTechniques.RandomPasswordTechnique;
using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class RandomPasswordTechniqueUiPage : PasswordGeneratorContentView
{
    private readonly IRandomPasswordTechnique randomPasswordTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public RandomPasswordTechniqueUiPage(IRandomPasswordTechnique randomPasswordTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        RegisterAddToVaultHost(addToVaultHost);
        this.randomPasswordTechnique = randomPasswordTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        analysisPanel?.Reset();
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        if (int.TryParse(lengthEntry?.Text, out int length) && length > 0)
        {
            bool includeUppercase = uppercaseCheckBox?.IsChecked ?? true;
            bool includeLowercase = lowercaseCheckBox?.IsChecked ?? true;
            bool includeDigits = digitsCheckBox?.IsChecked ?? true;
            bool includeSpecial = specialCheckBox?.IsChecked ?? true;
            string? seed = string.IsNullOrWhiteSpace(seedEntry?.Text) ? null : seedEntry.Text;
            seedWarning.IsVisible = seed is not null;

            string result = randomPasswordTechnique.GeneratePassword(length, includeUppercase, includeLowercase, includeDigits, includeSpecial, seed);
            
            if (resultEntry is not null)
            {
                resultEntry.Text = result;
            }

            UpdateGeneratedPassword(result);

            if (seed is not null)
            {
                analysisPanel?.Reset();
            }
            else if (analysisPanel is not null)
            {
                var bits = RandomPasswordTechnique.MinimumEntropyBits(length,
                    includeUppercase, includeLowercase, includeDigits, includeSpecial);
                var analysis = entropyAnalyzer.Analyze(result) with
                {
                    Entropy = Math.Round(bits, 2),
                    StrengthScore = Math.Min(bits / 80d, 1d) * 100d,
                    StrengthLabel = bits >= 80 ? "Stark" : bits >= 50 ? "Solide" : "Schwach",
                    Suggestions = bits >= 80
                        ? new[] { "Die Angabe ist eine konservative Untergrenze aus dem Zufallsverfahren." }
                        : new[] { "Erhöhe die Länge, um mehr zufällige Möglichkeiten zu erhalten." }
                };
                analysisPanel.Update(analysis);
            }
        }
        else
        {
            seedWarning.IsVisible = false;
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

            await Password_Phrase_Producer.Services.SensitiveClipboard.CopyAsync(resultEntry!.Text);
            await ToastService.ShowCopiedAsync("Passwort");
        }
    }
}

