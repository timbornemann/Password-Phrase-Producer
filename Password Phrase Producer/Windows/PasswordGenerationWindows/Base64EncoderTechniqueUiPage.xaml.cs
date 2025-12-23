using System;
using Password_Phrase_Producer.PasswordGenerationTechniques.Base64EncoderTechnique;
using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class Base64EncoderTechniqueUiPage : PasswordGeneratorContentView
{
    private readonly IBase64EncoderTechnique base64EncoderTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public Base64EncoderTechniqueUiPage(IBase64EncoderTechnique base64EncoderTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        RegisterAddToVaultHost(addToVaultHost);
        this.base64EncoderTechnique = base64EncoderTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        analysisPanel?.Reset();
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        string password = passwordEntry?.Text ?? string.Empty;

        if (!string.IsNullOrWhiteSpace(password))
        {
            string result = base64EncoderTechnique.GeneratePassword(password);
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

