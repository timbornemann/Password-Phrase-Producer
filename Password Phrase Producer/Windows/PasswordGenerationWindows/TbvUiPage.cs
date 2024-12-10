using Password_Phrase_Producer.PasswordGenerationTechniques.TbvTechniques;

namespace Password_Phrase_Producer.Windows.PasswordGenerationWindows;

public partial class TbvUiPage : ContentView
{
    private Entry passwordEntry;
    private Entry code1Entry;
    private Entry code2Entry;
    private Entry code3Entry;
    private Entry resultEntry;
    Itbv tbv;

    public TbvUiPage(Itbv itbv)
    {
        tbv = itbv;

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

        code1Entry = new Entry
        {
            Placeholder = "Code 1",
            TextColor = Colors.White,
            PlaceholderColor = Color.FromArgb("#AAAAAA"),
            BackgroundColor = Color.FromArgb("#333333"),
            Margin = new Thickness(5),
            FontSize = 18,
            HorizontalOptions = LayoutOptions.FillAndExpand,
            VerticalOptions = LayoutOptions.FillAndExpand
        };

        code2Entry = new Entry
        {
            Placeholder = "Code 2",
            TextColor = Colors.White,
            PlaceholderColor = Color.FromArgb("#AAAAAA"),
            BackgroundColor = Color.FromArgb("#333333"),
            Margin = new Thickness(5),
            FontSize = 18,
            HorizontalOptions = LayoutOptions.FillAndExpand,
            VerticalOptions = LayoutOptions.FillAndExpand
        };

        code3Entry = new Entry
        {
            Placeholder = "Code 3",
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
                code1Entry,
                code2Entry,
                code3Entry,
                resultEntry,
                createButton
            }
        };

        passwordEntry.SetBinding(Entry.TextProperty, "PasswordPhrase");
        code1Entry.SetBinding(Entry.TextProperty, "Code1");
        code2Entry.SetBinding(Entry.TextProperty, "Code2");
        code3Entry.SetBinding(Entry.TextProperty, "Code3");
        resultEntry.SetBinding(Entry.TextProperty, "Result");
    }

    private void CreatePassword(object sender, EventArgs e)
    {
        string password = passwordEntry.Text;
        int code1;
        int code2;
        int code3;

        bool c1 = int.TryParse(code1Entry.Text, out code1);
        bool c2 = int.TryParse(code2Entry.Text, out code2);
        bool c3 = int.TryParse(code3Entry.Text, out code3);

        if (c1 && c2 && c3)
        {
            string result = tbv.GeneratePassword(password, code1, code2, code3);
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
