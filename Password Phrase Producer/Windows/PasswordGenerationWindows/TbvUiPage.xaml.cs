using System;
using Password_Phrase_Producer.PasswordGenerationTechniques.TbvTechniques;
using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class TbvUiPage : PasswordGeneratorContentView
{
    private readonly Itbv tbv;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public TbvUiPage(Itbv itbv, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        RegisterAddToVaultHost(addToVaultHost);
        tbv = itbv;
        this.entropyAnalyzer = entropyAnalyzer;

        analysisPanel?.Reset();
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        var password = passwordEntry?.Text;

        if (string.IsNullOrWhiteSpace(password))
        {
            resultEntry.Text = string.Empty;
            UpdateGeneratedPassword(null);
            return;
        }

        bool c1 = int.TryParse(code1Entry?.Text, out var code1);
        bool c2 = int.TryParse(code2Entry?.Text, out var code2);
        bool c3 = int.TryParse(code3Entry?.Text, out var code3);

        if (c1 && c2 && c3)
        {
            string result = tbv.GeneratePassword(password, code1, code2, code3);
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
