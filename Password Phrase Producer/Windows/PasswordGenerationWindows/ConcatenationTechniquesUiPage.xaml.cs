using System;
using System.Collections.Generic;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class ConcatenationTechniquesUiPage : ContentView
{
    private readonly IConcatenationTechnique concatenationTechnique;
    private const int InitialEntryCount = 4;

    public ConcatenationTechniquesUiPage(IConcatenationTechnique concatenationTechnique)
    {
        InitializeComponent();
        this.concatenationTechnique = concatenationTechnique;

        for (int i = 0; i < InitialEntryCount; i++)
        {
            phraseContainer.Children.Add(CreatePhraseEntry());
        }
    }

    private void OnAddNewTextField(object? sender, EventArgs e)
    {
        phraseContainer.Children.Add(CreatePhraseEntry());
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

    private void OnCreateClicked(object sender, EventArgs e)
    {
        var phrases = new List<string>();

        foreach (var child in phraseContainer.Children)
        {
            if (child is Entry entry && !string.IsNullOrWhiteSpace(entry.Text))
            {
                phrases.Add(entry.Text);
            }
        }

        var result = concatenationTechnique.EncryptPassword(phrases);
        if (resultEntry is not null)
        {
            resultEntry.Text = result;
        }
    }

    private View CreatePhraseEntry()
    {
        var entry = new Entry
        {
            Placeholder = "Phrase"
        };

        if (Application.Current?.Resources.TryGetValue("DarkEntryStyle", out var styleObj) == true && styleObj is Style style)
        {
            entry.Style = style;
        }

        return entry;
    }
}
