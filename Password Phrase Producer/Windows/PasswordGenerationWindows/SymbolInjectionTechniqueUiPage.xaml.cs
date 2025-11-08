using System;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.PasswordGenerationTechniques.SymbolInjectionTechnique;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class SymbolInjectionTechniqueUiPage : ContentView
{
    private readonly ISymbolInjectionTechnique symbolInjectionTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;

    public SymbolInjectionTechniqueUiPage(ISymbolInjectionTechnique symbolInjectionTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        this.symbolInjectionTechnique = symbolInjectionTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        UpdateSymbolLabel();
        analysisPanel?.Reset();
    }

    private void OnSymbolCountChanged(object? sender, ValueChangedEventArgs e)
    {
        UpdateSymbolLabel();
    }

    private void UpdateSymbolLabel()
    {
        if (symbolLabel is not null)
        {
            symbolLabel.Text = $"Symbole: {GetSymbolCount()}";
        }
    }

    private int GetSymbolCount()
    {
        return symbolSlider is null ? 2 : (int)Math.Round(symbolSlider.Value);
    }

    private void OnCreateClicked(object sender, EventArgs e)
    {
        string input = inputEntry?.Text ?? string.Empty;
        int symbolCount = GetSymbolCount();
        bool randomizeCase = caseSwitch?.IsToggled ?? false;
        string seed = seedEntry?.Text ?? string.Empty;

        string result = symbolInjectionTechnique.InjectSymbols(input, symbolCount, randomizeCase, string.IsNullOrWhiteSpace(seed) ? null : seed);

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
