using System;
using System.Linq;
using System.Text;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows.Controls;

public partial class PasswordAnalysisPanel : ContentView
{
    private EntropyAnalysisResult? currentResult;

    public PasswordAnalysisPanel()
    {
        InitializeComponent();
    }

    public void Update(EntropyAnalysisResult analysisResult)
    {
        currentResult = analysisResult;

        strengthLabel.Text = $"Stärke: {analysisResult.StrengthLabel} ({analysisResult.StrengthScore:F0}%)";
        strengthBar.Progress = Math.Clamp(analysisResult.StrengthScore / 100d, 0d, 1d);
        entropyLabel.Text = $"Entropie: {analysisResult.Entropy:F1} Bit";
        characterSetLabel.Text = $"Zeichenräume: {analysisResult.CharacterSetSize} · Gruppen: {analysisResult.CharacterGroupCount}";

        if (analysisResult.Suggestions.Count > 0)
        {
            suggestionsLabel.Text = string.Join("\n", analysisResult.Suggestions.Select(s => $"• {s}"));
            suggestionBorder.IsVisible = true;
        }
        else
        {
            suggestionBorder.IsVisible = false;
            suggestionsLabel.Text = string.Empty;
        }

        analysisBorder.IsVisible = true;
        IsVisible = true;
    }

    public void Reset()
    {
        currentResult = null;
        analysisBorder.IsVisible = false;
        IsVisible = false;
        strengthBar.Progress = 0;
        strengthLabel.Text = "Stärke: -";
        entropyLabel.Text = "Entropie: -";
        characterSetLabel.Text = "Zeichenräume: -";
        suggestionsLabel.Text = string.Empty;
        suggestionBorder.IsVisible = false;
    }

    private async void OnInfoTapped(object? sender, EventArgs e)
    {
        if (currentResult is null)
        {
            return;
        }

        var breakdown = currentResult.Breakdown;
        var builder = new StringBuilder();
        builder.AppendLine($"Passwortlänge: {currentResult.Length}");
        builder.AppendLine($"Entropie: {currentResult.Entropy:F2} Bit");
        builder.AppendLine($"Zeichensatz: {currentResult.CharacterSetSize} mögliche Zeichen");
        builder.AppendLine();
        builder.AppendLine("Zeichenklassen:");
        builder.AppendLine($"  • Großbuchstaben: {breakdown.Uppercase}");
        builder.AppendLine($"  • Kleinbuchstaben: {breakdown.Lowercase}");
        builder.AppendLine($"  • Ziffern: {breakdown.Digits}");
        builder.AppendLine($"  • Sonderzeichen: {breakdown.Symbols}");
        builder.AppendLine($"  • Leerzeichen: {breakdown.Spaces}");

        string details = builder.ToString();

        var page = this.Window?.Page ?? Application.Current?.Windows[0]?.Page;
        if (page is not null)
        {
            await page.DisplayAlert("Detaillierte Analyse", details, "Schließen");
        }
    }
}
