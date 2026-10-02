using System;
using System.Collections.Generic;
using Microsoft.Maui;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques;
using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Services.EntropyAnalyzer;
using Password_Phrase_Producer.Views.Controls;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class ConcatenationTechniquesUiPage : PasswordGeneratorContentView
{
    private readonly IConcatenationTechnique concatenationTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;
    private const int InitialEntryCount = 4;

    public ConcatenationTechniquesUiPage(IConcatenationTechnique concatenationTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
        RegisterAddToVaultHost(addToVaultHost);
        this.concatenationTechnique = concatenationTechnique;
        this.entropyAnalyzer = entropyAnalyzer;

        analysisPanel?.Reset();

        for (int i = 0; i < InitialEntryCount; i++)
        {
            phraseContainer.Children.Add(CreatePhraseEntry());
        }

        UpdatePhraseEntryIndices();
    }

    private void OnAddNewTextField(object? sender, EventArgs e)
    {
        phraseContainer.Children.Add(CreatePhraseEntry());
        UpdatePhraseEntryIndices();
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

    private void OnCreateClicked(object sender, EventArgs e)
    {
        var phrases = new List<string>();

        foreach (var child in phraseContainer.Children)
        {
            if (child is Grid row && row.Children.Count > 1 &&
                row.Children[1] is Entry entry && !string.IsNullOrWhiteSpace(entry.Text))
            {
                phrases.Add(entry.Text);
            }
        }

        var result = concatenationTechnique.EncryptPassword(phrases);

        if (string.IsNullOrWhiteSpace(result))
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

    private Grid CreatePhraseEntry()
    {
        var indexLabel = new Label
        {
            Text = "01",
            FontSize = 12,
            WidthRequest = 28,
            VerticalTextAlignment = TextAlignment.Center
        };
        indexLabel.SetDynamicResource(Label.TextColorProperty, "TextTertiary");

        var entry = new FramedEntry
        {
            Placeholder = "Phrase",
            HorizontalOptions = LayoutOptions.Fill,
            VerticalOptions = LayoutOptions.Center
        };

        if (Application.Current?.Resources.TryGetValue("DarkEntryStyle", out var styleObj) == true && styleObj is Style style)
        {
            entry.Style = style;
        }

        var row = new Grid
        {
            ColumnDefinitions =
            {
                new ColumnDefinition { Width = GridLength.Auto },
                new ColumnDefinition { Width = GridLength.Star }
            },
            ColumnSpacing = 8
        };
        row.Children.Add(indexLabel);
        row.Children.Add(entry);
        Grid.SetColumn(entry, 1);

        return row;
    }

    private void UpdatePhraseEntryIndices()
    {
        int index = 1;

        foreach (var child in phraseContainer.Children)
        {
            if (child is Grid row && row.Children.Count > 1 &&
                row.Children[0] is Label indexLabel && row.Children[1] is Entry entry)
            {
                indexLabel.Text = index.ToString("D2");
                entry.Placeholder = $"Phrase {index}";
            }

            index++;
        }
    }
}
