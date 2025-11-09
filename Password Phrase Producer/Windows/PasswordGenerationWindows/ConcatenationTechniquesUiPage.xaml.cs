using System;
using System.Collections.Generic;
using Microsoft.Maui;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Controls.Shapes;
using Microsoft.Maui.Graphics;
using Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class ConcatenationTechniquesUiPage : PasswordGeneratorContentView
{
    private readonly IConcatenationTechnique concatenationTechnique;
    private readonly IPasswordEntropyAnalyzer entropyAnalyzer;
    private const int InitialEntryCount = 4;

    public ConcatenationTechniquesUiPage(IConcatenationTechnique concatenationTechnique, IPasswordEntropyAnalyzer entropyAnalyzer)
    {
        InitializeComponent();
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
            if (TryGetEntry(child, out var entry) && !string.IsNullOrWhiteSpace(entry.Text))
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

    private View CreatePhraseEntry()
    {
        var indexLabel = new Label
        {
            Text = "1",
            FontSize = 16,
            FontAttributes = FontAttributes.Bold,
            TextColor = Colors.White,
            HorizontalTextAlignment = TextAlignment.Center,
            VerticalTextAlignment = TextAlignment.Center
        };

        var indexBorder = new Border
        {
            WidthRequest = 38,
            HeightRequest = 38,
            BackgroundColor = Color.FromArgb("#2F3452"),
            StrokeThickness = 0,
            HorizontalOptions = LayoutOptions.Center,
            VerticalOptions = LayoutOptions.Center,
            Content = indexLabel
        };

        indexBorder.StrokeShape = new RoundRectangle { CornerRadius = 14 };

        var entry = new Entry
        {
            Placeholder = "Phrase",
            HorizontalOptions = LayoutOptions.Fill,
            VerticalOptions = LayoutOptions.Center
        };

        if (Application.Current?.Resources.TryGetValue("DarkEntryStyle", out var styleObj) == true && styleObj is Style style)
        {
            entry.Style = style;
        }

        var grid = new Grid
        {
            ColumnDefinitions =
            {
                new ColumnDefinition { Width = GridLength.Auto },
                new ColumnDefinition { Width = GridLength.Star }
            },
            ColumnSpacing = 16,
            RowDefinitions =
            {
                new RowDefinition { Height = GridLength.Auto }
            },
            Padding = new Thickness(0),
            VerticalOptions = LayoutOptions.Fill
        };

        grid.Children.Add(indexBorder);
        Grid.SetColumn(indexBorder, 0);

        grid.Children.Add(entry);
        Grid.SetColumn(entry, 1);

        return grid;
    }

    private static bool TryGetEntry(IView container, out Entry? entry)
    {
        switch (container)
        {
            case Entry directEntry:
                entry = directEntry;
                return true;
            case Grid grid:
                foreach (var child in grid.Children)
                {
                    if (TryGetEntry(child, out entry))
                    {
                        return true;
                    }
                }

                entry = null;
                return false;
            case Layout layout:
                foreach (var child in layout.Children)
                {
                    if (TryGetEntry(child, out entry))
                    {
                        return true;
                    }
                }

                entry = null;
                return false;
            case Border border when border.Content is IView view:
                return TryGetEntry(view, out entry);
            default:
                entry = null;
                return false;
        }
    }

    private void UpdatePhraseEntryIndices()
    {
        int index = 1;

        foreach (var child in phraseContainer.Children)
        {
            if (child is Grid grid)
            {
                foreach (var element in grid.Children)
                {
                    if (element is Border badge && badge.Content is Label badgeLabel)
                    {
                        badgeLabel.Text = index.ToString();
                    }
                    else if (element is Entry entry)
                    {
                        entry.Placeholder = $"Phrase {index}";
                    }
                }
            }

            index++;
        }

        if (phraseCountLabel is not null)
        {
            phraseCountLabel.Text = $"Phrasen ({phraseContainer.Children.Count})";
        }
    }
}
