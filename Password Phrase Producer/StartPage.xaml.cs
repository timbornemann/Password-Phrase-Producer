using Password_Phrase_Producer.ViewModels;

namespace Password_Phrase_Producer;

public partial class StartPage : ContentPage
{
    public StartPage()
    {
        InitializeComponent();
        BindingContext = new StartPageViewModel();
    }
}
