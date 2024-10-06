using Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows
{
    public partial class ConcatenationTechniquesUiPage : ContentView
    {
        private IConcatenationTechnique concatenationTechnique;

        private ScrollView scrollView;
        private VerticalStackLayout verticalStackLayout;
        private Entry resultEntry;
        private const int MaxVisibleEntries = 4;


        public ConcatenationTechniquesUiPage(IConcatenationTechnique concatenationTechnique)
        {
            this.concatenationTechnique = concatenationTechnique;

            var addNewTextfieldButton = new Button
            {
                Text = "New Entry",
                BackgroundColor = Color.FromArgb("#4CAF50"),
                TextColor = Colors.White,
                CornerRadius = 25,
                FontSize = 18,
                HeightRequest = 50,
                Margin = new Thickness(5),
                HorizontalOptions = LayoutOptions.FillAndExpand,
                VerticalOptions = LayoutOptions.End
            };

            addNewTextfieldButton.Clicked += AddNewTextfieldButton_Clicked;

            verticalStackLayout = new VerticalStackLayout
            {
                Spacing = 10,
            };

            for (int i = 0; i < MaxVisibleEntries; i++)
            {
                verticalStackLayout.Children.Add(EntryFactory());
            }

            verticalStackLayout.Children.Add(addNewTextfieldButton);

            scrollView = new ScrollView
            {
                Content = verticalStackLayout,
                VerticalOptions = LayoutOptions.FillAndExpand,
                HeightRequest = 200 
            };

            resultEntry = new Entry
            {
                Placeholder = "Result",
                TextColor = Colors.White,
                PlaceholderColor = Color.FromArgb("#AAAAAA"),
                BackgroundColor = Color.FromArgb("#333333"),
                Margin = new Thickness(5),
                FontSize = 18,
                HorizontalOptions = LayoutOptions.FillAndExpand,
                VerticalOptions = LayoutOptions.FillAndExpand
            };

            resultEntry.Focused += CopyPassword;

            var createButton = new Button
            {
                Text = "Create",
                BackgroundColor = Color.FromArgb("#4CAF50"),
                TextColor = Colors.White,
                CornerRadius = 25,
                FontSize = 18,
                HeightRequest = 50,
                Margin = new Thickness(5),
                HorizontalOptions = LayoutOptions.FillAndExpand,
                VerticalOptions = LayoutOptions.FillAndExpand
            };

            createButton.Clicked += CreatePassword;

            Content = new VerticalStackLayout
            {
                Padding = new Thickness(20),
                Spacing = 15, 
                Children =
                {
                    scrollView,
                    resultEntry, 
                    createButton 
                }
            };
        }

        private Entry EntryFactory()
        {
            return new Entry
            {
                Placeholder = "Phrase",
                TextColor = Colors.White,
                PlaceholderColor = Color.FromArgb("#AAAAAA"),
                BackgroundColor = Color.FromArgb("#333333"),
                Margin = new Thickness(5),
                FontSize = 18,
                HorizontalOptions = LayoutOptions.FillAndExpand,
                VerticalOptions = LayoutOptions.FillAndExpand
            };
        }

        private void AddNewTextfieldButton_Clicked(object? sender, EventArgs e)
        {
            verticalStackLayout.Children.Insert(verticalStackLayout.Children.Count - 1, EntryFactory()); 
        }

        private void CreatePassword(object sender, EventArgs e)
        {
            List<string> phrases = new List<string>();

            foreach (var child in verticalStackLayout.Children)
            {
                if (child is Entry entry && entry.Text != null)
                {
                    phrases.Add(entry.Text);
                }
            }

            string result = concatenationTechnique.EncryptPassword(phrases);
            resultEntry.Text = result;
        }

        private async void CopyPassword(object sender, FocusEventArgs e)
        {
            if (!string.IsNullOrEmpty(resultEntry.Text))
            {
                await Clipboard.Default.SetTextAsync(resultEntry.Text);
                await Application.Current.MainPage.DisplayAlert("Info", "Passsword is copied", "OK");
            }
            resultEntry.Unfocus();
        }

    }
}
