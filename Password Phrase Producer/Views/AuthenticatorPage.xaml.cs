using Password_Phrase_Producer.ViewModels;

namespace Password_Phrase_Producer.Views;

public partial class AuthenticatorPage : ContentPage
{
    private readonly AuthenticatorViewModel _viewModel;

    public AuthenticatorPage(AuthenticatorViewModel viewModel)
    {
        InitializeComponent();
        BindingContext = _viewModel = viewModel;
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        _viewModel.Activate();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _viewModel.Deactivate();
    }
}
