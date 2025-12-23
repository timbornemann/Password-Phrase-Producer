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

            string result = randomPasswordTechnique.GeneratePassword(length, includeUppercase, includeLowercase, includeDigits, includeSpecial, seed);
            
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
            await ToastService.ShowCopiedAsync("Passwort");
        }
    }
}

