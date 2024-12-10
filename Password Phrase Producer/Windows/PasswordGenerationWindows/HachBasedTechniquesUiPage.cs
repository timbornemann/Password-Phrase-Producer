using Password_Phrase_Producer.PasswordGenerationTechniques.HashBasedTechniques;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows
{
    internal class HachBasedTechniquesUiPage : ContentView
    {

        IHashBasedTechniques hashBasedTechnique;

        private Entry passwordEntry;
        private Entry resultEntry;

        public HachBasedTechniquesUiPage(IHashBasedTechniques hashBasedTechnique)
        {
            this.hashBasedTechnique = hashBasedTechnique;

            passwordEntry = new Entry
            {
                Placeholder = "Password phrase",
                TextColor = Colors.White,
                PlaceholderColor = Color.FromArgb("#AAAAAA"),
                BackgroundColor = Color.FromArgb("#333333"),
                Margin = new Thickness(5),
                FontSize = 18,
                HorizontalOptions = LayoutOptions.FillAndExpand,
                VerticalOptions = LayoutOptions.FillAndExpand
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
                Children =
            {
                passwordEntry,
                resultEntry,
                createButton
            }
            };

            passwordEntry.SetBinding(Entry.TextProperty, "PasswordPhrase");
            resultEntry.SetBinding(Entry.TextProperty, "Result");




        }

        private void CreatePassword(object sender, EventArgs e)
        {
            string password = passwordEntry.Text;

            if (!string.IsNullOrWhiteSpace(password))
            {
                string result = hashBasedTechnique.GeneratePassword(password);
                resultEntry.Text = result;
            }


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
