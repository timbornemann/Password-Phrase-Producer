using System;
using Password_Phrase_Producer.PasswordGenerationTechniques.SegmentRotationTechnique;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class SegmentRotationTechniqueUiPage : PasswordGeneratorContentView
{
    private readonly ISegmentRotationTechnique rotationTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public SegmentRotationTechniqueUiPage(ISegmentRotationTechnique rotationTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        RegisterAddToVaultHost(addToVaultHost);
        this.rotationTechnique = rotationTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        UpdateSegmentLabel();
        analysisPanel?.Reset();
    }

    private void OnSegmentLengthChanged(object? sender, ValueChangedEventArgs e)
    {
        UpdateSegmentLabel();
    }

    private void UpdateSegmentLabel()
    {
        if (segmentLabel is not null)
        {
            segmentLabel.Text = $"Segmentlänge: {GetSegmentLength()}";
        }
    }

    private int GetSegmentLength()
    {
        return segmentSlider is null ? 3 : (int)Math.Round(segmentSlider.Value);
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        string input = inputEntry?.Text ?? string.Empty;
        int segmentLength = GetSegmentLength();
        string result = rotationTechnique.ShuffleSegments(input, segmentLength);

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
